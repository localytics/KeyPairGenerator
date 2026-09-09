package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dir := flag.String("dir", ".", "directory for rsa_key.p8 and rsa_key.pub")
	generate := flag.Bool("generate", false, "create a new unencrypted PKCS#8 key pair")
	force := flag.Bool("force", false, "overwrite existing key files when generating")
	bits := flag.Int("bits", 2048, "RSA key size when generating")
	flag.Parse()

	privatePath := filepath.Join(*dir, "rsa_key.p8")
	publicPath := filepath.Join(*dir, "rsa_key.pub")

	if *generate {
		if err := writeNewKeyPair(privatePath, publicPath, *bits, *force); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", privatePath)
		fmt.Fprintf(os.Stderr, "wrote %s\n", publicPath)
	}

	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		fatal(err)
	}
	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		fatal(err)
	}

	if err := requirePEMHeader(privatePEM, "-----BEGIN PRIVATE KEY-----"); err != nil {
		fatal(err)
	}
	if err := requirePEMHeader(publicPEM, "-----BEGIN PUBLIC KEY-----"); err != nil {
		fatal(err)
	}

	fmt.Println("AWS secret key: SNOWFLAKE_PRIVATE_KEY_B64")
	fmt.Println(base64.StdEncoding.EncodeToString(privatePEM))
	fmt.Println()
	fmt.Println("Snowflake:")
	fmt.Printf("ALTER USER auditorium SET RSA_PUBLIC_KEY='%s';\n", pemBody(publicPEM))
}

func writeNewKeyPair(privatePath, publicPath string, bits int, force bool) error {
	if !force {
		for _, path := range []string{privatePath, publicPath} {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists; pass -force to overwrite", path)
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(publicPath, publicPEM, 0o644)
}

func requirePEMHeader(pem []byte, header string) error {
	if !strings.Contains(string(pem), header) {
		return fmt.Errorf("expected %s", header)
	}
	if strings.Contains(string(pem), "BEGIN ENCRYPTED PRIVATE KEY") {
		return fmt.Errorf("key is encrypted; generate an unencrypted PKCS#8 PEM first")
	}
	return nil
}

func pemBody(pem []byte) string {
	var body []string
	for _, line := range strings.Split(string(pem), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "BEGIN") || strings.Contains(line, "END") {
			continue
		}
		body = append(body, line)
	}
	return strings.Join(body, "")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
