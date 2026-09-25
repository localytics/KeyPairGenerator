// Command keypair-generator generates or reads a PKCS#8 RSA key pair and
// prints Snowflake / AWS secret values. A passphrase encrypts the private key.
package main

import (
	"fmt"
	"os"

	"github.com/localytics/KeyPairGenerator/internal/cli"
)

func main() {
	cmd := cli.New()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}
