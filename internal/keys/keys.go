// Package keys generates and validates PKCS#8 RSA key files for Snowflake
// key-pair authentication. A non-empty passphrase encrypts the private key.
package keys

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/youmark/pkcs8"
)

const (
	// PrivateFile is the PKCS#8 private-key filename written next to PublicFile.
	PrivateFile = "rsa_key.p8"
	// PublicFile is the PKIX public-key filename written next to PrivateFile.
	PublicFile = "rsa_key.pub"
	// OutputFile is the filename that receives the Base64 values.
	OutputFile = "output.txt"
	// MinBits is the smallest RSA modulus this package will generate.
	MinBits = 2048
)

const pemEncryptedPrivate = "ENCRYPTED PRIVATE KEY"

var (
	// ErrExists reports that a key file is already on disk and --force was not set.
	ErrExists = errors.New("keys: file already exists")
	// ErrEncrypted reports that the private PEM is an encrypted PKCS#8 key
	// and no passphrase was provided.
	ErrEncrypted = errors.New("keys: private key is encrypted")
	// ErrPassphrase reports that the passphrase did not decrypt the private key.
	ErrPassphrase = errors.New("keys: wrong passphrase")
	// ErrBitsTooSmall reports that --bits is below MinBits.
	ErrBitsTooSmall = errors.New("keys: bits below minimum")
	// ErrPEMType reports that a PEM block is not the expected type.
	ErrPEMType = errors.New("keys: unexpected pem type")
	// ErrPEMMissing reports that the file does not contain a PEM block.
	ErrPEMMissing = errors.New("keys: missing pem block")
	// ErrKeyMismatch reports that the public key does not correspond to the private key.
	ErrKeyMismatch = errors.New("keys: public key does not match private key")
	// ErrNotRSA reports that a private key is not an RSA key.
	ErrNotRSA = errors.New("keys: private key is not RSA")
)

// pkcs8EncryptOpts is PBES2 AES-256-CBC with PBKDF2-HMAC-SHA256, which
// Snowflake Go clients can decrypt. IterationCount is the OWASP 2023 floor.
var pkcs8EncryptOpts = &pkcs8.Opts{
	Cipher: pkcs8.AES256CBC,
	KDFOpts: pkcs8.PBKDF2Opts{
		SaltSize:       16,
		IterationCount: 600000,
		HMACHash:       crypto.SHA256,
	},
}

// WriteNewPair creates a PKCS#8 private key and matching PKIX public key.
// A non-empty passphrase writes an encrypted private key. It refuses to
// overwrite existing files unless force is true. bits must be at least MinBits.
//
// The private file is written first (mode 0600). If the public write fails,
// the private file is removed so a half-written pair is not left behind.
func WriteNewPair(privatePath, publicPath string, bits int, force bool, passphrase string) error {
	if bits < MinBits {
		return fmt.Errorf("%w: %d < %d", ErrBitsTooSmall, bits, MinBits)
	}

	if !force {
		for _, path := range []string{privatePath, publicPath} {
			_, err := os.Stat(path)
			switch {
			case err == nil:
				return fmt.Errorf("%w: %s", ErrExists, path)
			case errors.Is(err, fs.ErrNotExist):
				// path is free
			default:
				return fmt.Errorf("stat %s: %w", path, err)
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}

	privatePEM, err := marshalPrivatePEM(key, passphrase)
	if err != nil {
		return err
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}

	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", privatePath, err)
	}

	//nolint:gosec // G306: public key is not secret; 0644 is the intended mode
	if err := os.WriteFile(publicPath, publicPEM, 0o644); err != nil {
		if removeErr := os.Remove(privatePath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return errors.Join(
				fmt.Errorf("write %s: %w", publicPath, err),
				fmt.Errorf("remove %s: %w", privatePath, removeErr),
			)
		}

		return fmt.Errorf("write %s: %w", publicPath, err)
	}

	return nil
}

// ReadAndValidate loads both PEM files and checks they are PKCS#8 / PKIX
// blocks. Encrypted private keys fail unless passphrase decrypts them.
func ReadAndValidate(privatePath, publicPath, passphrase string) (privatePEM, publicPEM []byte, err error) {
	//nolint:gosec // G304: paths are chosen by the operator via --dir
	privatePEM, err = os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", privatePath, err)
	}

	//nolint:gosec // G304: paths are chosen by the operator via --dir
	publicPEM, err = os.ReadFile(publicPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", publicPath, err)
	}

	if err := validatePrivate(privatePEM, passphrase); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", privatePath, err)
	}

	if err := requireBlock(publicPEM, "PUBLIC KEY"); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", publicPath, err)
	}

	return privatePEM, publicPEM, nil
}

// PEMBody returns the base64 body of the first PEM block, which Snowflake
// expects for ALTER USER ... SET RSA_PUBLIC_KEY. The PEM headers and
// newlines are not included.
func PEMBody(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", ErrPEMMissing
	}

	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

// VerifyMatch reports whether the public key encoded in publicPEM is the one
// that corresponds to privatePEM. passphrase decrypts an encrypted private key.
// Callers should run ReadAndValidate first so both blocks are already known
// to be well-formed PKCS#8/PKIX PEM.
func VerifyMatch(privatePEM, publicPEM []byte, passphrase string) error {
	privateBlock, _ := pem.Decode(privatePEM)
	if privateBlock == nil {
		return ErrPEMMissing
	}

	rsaKey, err := rsaPrivateKey(privateBlock, passphrase)
	if err != nil {
		return err
	}

	publicBlock, _ := pem.Decode(publicPEM)
	if publicBlock == nil {
		return ErrPEMMissing
	}

	wantDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal derived public key: %w", err)
	}

	if !bytes.Equal(wantDER, publicBlock.Bytes) {
		return ErrKeyMismatch
	}

	return nil
}

func marshalPrivatePEM(key *rsa.PrivateKey, passphrase string) ([]byte, error) {
	if passphrase == "" {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal private key: %w", err)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}

	der, err := pkcs8.MarshalPrivateKey(key, []byte(passphrase), pkcs8EncryptOpts)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemEncryptedPrivate, Bytes: der}), nil
}

func validatePrivate(pemBytes []byte, passphrase string) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ErrPEMMissing
	}

	switch block.Type {
	case pemEncryptedPrivate:
		if passphrase == "" {
			return ErrEncrypted
		}

		_, err := rsaPrivateKey(block, passphrase)

		return err
	case "PRIVATE KEY":
		return nil
	default:
		return fmt.Errorf("%w: %q, want %q", ErrPEMType, block.Type, "PRIVATE KEY")
	}
}

func rsaPrivateKey(block *pem.Block, passphrase string) (*rsa.PrivateKey, error) {
	var (
		parsed any
		err    error
	)

	if block.Type == pemEncryptedPrivate {
		if passphrase == "" {
			return nil, ErrEncrypted
		}

		parsed, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrPassphrase, err)
		}
	} else {
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSA
	}

	return rsaKey, nil
}

func requireBlock(pemBytes []byte, wantType string) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ErrPEMMissing
	}

	if block.Type == pemEncryptedPrivate {
		return ErrEncrypted
	}

	if block.Type != wantType {
		return fmt.Errorf("%w: %q, want %q", ErrPEMType, block.Type, wantType)
	}

	return nil
}
