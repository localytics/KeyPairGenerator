package keys

import (
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNewPairAndRead(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, PrivateFile)
	publicPath := filepath.Join(dir, PublicFile)

	if err := WriteNewPair(privatePath, publicPath, MinBits, false); err != nil {
		t.Fatal(err)
	}

	privatePEM, publicPEM, err := ReadAndValidate(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := PEMBody(publicPEM); err != nil {
		t.Fatal(err)
	}

	if len(privatePEM) == 0 || len(publicPEM) == 0 {
		t.Fatal("expected pem bytes")
	}

	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private mode %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteNewPairExists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, PrivateFile)
	publicPath := filepath.Join(dir, PublicFile)

	if err := WriteNewPair(privatePath, publicPath, MinBits, false); err != nil {
		t.Fatal(err)
	}

	err := WriteNewPair(privatePath, publicPath, MinBits, false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("error %v, want ErrExists", err)
	}

	if err := WriteNewPair(privatePath, publicPath, MinBits, true); err != nil {
		t.Fatal(err)
	}
}

func TestWriteNewPairBitsTooSmall(t *testing.T) {
	t.Parallel()

	err := WriteNewPair("unused.p8", "unused.pub", 1024, true)
	if !errors.Is(err, ErrBitsTooSmall) {
		t.Fatalf("error %v, want ErrBitsTooSmall", err)
	}
}

func TestWriteNewPairRemovesPrivateOnPublicFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, PrivateFile)
	publicPath := filepath.Join(dir, PublicFile)

	if err := os.Mkdir(publicPath, 0o750); err != nil {
		t.Fatal(err)
	}

	err := WriteNewPair(privatePath, publicPath, MinBits, true)
	if err == nil {
		t.Fatal("expected error")
	}

	if _, statErr := os.Stat(privatePath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("private key should be removed, stat: %v", statErr)
	}
}

func TestReadAndValidateEncrypted(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, PrivateFile)
	publicPath := filepath.Join(dir, PublicFile)

	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("y")})

	if err := os.WriteFile(privatePath, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(publicPath, public, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := ReadAndValidate(privatePath, publicPath)
	if !errors.Is(err, ErrEncrypted) {
		t.Fatalf("error %v, want ErrEncrypted", err)
	}
}

func TestReadAndValidateMissingPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, PrivateFile)
	publicPath := filepath.Join(dir, PublicFile)

	if err := os.WriteFile(privatePath, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(publicPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := ReadAndValidate(privatePath, publicPath)
	if !errors.Is(err, ErrPEMMissing) {
		t.Fatalf("error %v, want ErrPEMMissing", err)
	}
}

func TestReadAndValidateHeaderCommentIsNotEnough(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, PrivateFile)
	publicPath := filepath.Join(dir, PublicFile)

	if err := os.WriteFile(privatePath, []byte("see -----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("y")}), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := ReadAndValidate(privatePath, publicPath)
	if !errors.Is(err, ErrPEMMissing) {
		t.Fatalf("error %v, want ErrPEMMissing", err)
	}
}

func TestPEMBody(t *testing.T) {
	t.Parallel()

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01, 0x02, 0x03}})

	got, err := PEMBody(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	if got != "AQID" {
		t.Fatalf("body %q, want AQID", got)
	}

	_, err = PEMBody([]byte("nope"))
	if !errors.Is(err, ErrPEMMissing) {
		t.Fatalf("error %v, want ErrPEMMissing", err)
	}
}
