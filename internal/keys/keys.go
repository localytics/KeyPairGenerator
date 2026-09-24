// Package keys generates and validates unencrypted PKCS#8 RSA key files
// for Snowflake key-pair authentication.
package keys

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
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

var (
	// ErrExists reports that a key file is already on disk and --force was not set.
	ErrExists = errors.New("keys: file already exists")
	// ErrEncrypted reports that the private PEM is an encrypted PKCS#8 key.
	ErrEncrypted = errors.New("keys: private key is encrypted")
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

// WriteNewPair creates an unencrypted PKCS#8 private key and matching PKIX
// public key. It refuses to overwrite existing files unless force is true.
// bits must be at least MinBits.
//
// The private file is written first (mode 0600). If the public write fails,
// the private file is removed so a half-written pair is not left behind.
func WriteNewPair(privatePath, publicPath string, bits int, force bool) error {
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

	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
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

// ReadAndValidate loads both PEM files and checks they are unencrypted
// PKCS#8 / PKIX blocks. Encrypted private keys and non-PEM files fail.
func ReadAndValidate(privatePath, publicPath string) (privatePEM, publicPEM []byte, err error) {
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

	if err := requireBlock(privatePEM, "PRIVATE KEY"); err != nil {
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
// that corresponds to privatePEM. Callers should run ReadAndValidate first so
// both blocks are already known to be well-formed PKCS#8/PKIX PEM.
func VerifyMatch(privatePEM, publicPEM []byte) error {
	privateBlock, _ := pem.Decode(privatePEM)
	if privateBlock == nil {
		return ErrPEMMissing
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return ErrNotRSA
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

func requireBlock(pemBytes []byte, wantType string) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ErrPEMMissing
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return ErrEncrypted
	}

	if block.Type != wantType {
		return fmt.Errorf("%w: %q, want %q", ErrPEMType, block.Type, wantType)
	}

	return nil
}
