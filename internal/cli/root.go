// Package cli implements the keypair-generator Cobra command tree.
package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/localytics/KeyPairGenerator/internal/keys"
)

// UsageError marks an invalid invocation (bad flags or extra args).
// main maps it to exit status 2.
type UsageError struct {
	Err error
}

func (e *UsageError) Error() string {
	return e.Err.Error()
}

func (e *UsageError) Unwrap() error {
	return e.Err
}

const defaultUser = "{}"

type options struct {
	dir        string
	user       string
	passphrase string
	generate   bool
	force      bool
	bits       int
}

// New returns a fresh command tree. Callers must not reuse the same
// command across Execute calls; Cobra accumulates flag state.
func New() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "keypair-generator",
		Short: "Generate Snowflake RSA key-pair values",
		Long: `keypair-generator creates or reads a PKCS#8 RSA key pair and writes
the AWS secret and Snowflake ALTER USER values to output.txt and stdout.

Every run reads rsa_key.p8 and rsa_key.pub, then writes output.txt (and prints the same text to stdout) with:

  1. SNOWFLAKE_PRIVATE_KEY_B64 — Base64 of the full private PEM (starts with LS0t). Store this as the AWS secret.
  2. A Snowflake ALTER USER ... SET RSA_PUBLIC_KEY statement with the public key body (no PEM headers).

Missing key files are an error unless --generate is also set. Pass --passphrase to encrypt a new private key, or to read an encrypted one. The passphrase is not written to output.txt.`,
		Example: `  # Create a new key pair in the current directory
  keypair-generator --generate

  # Write keys to another directory
  keypair-generator --dir ./keys --generate

  # Replace an existing pair with a 4096-bit key
  keypair-generator --generate --force --bits 4096

  # Encrypt the private key with a passphrase
  keypair-generator --generate --passphrase 'your passphrase'

  # Write values from keys that already exist
  keypair-generator

  # Name the Snowflake user in output.txt
  keypair-generator --user EXAMPLE_USER`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return &UsageError{Err: err}
			}

			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.dir, "dir", "d", ".", "directory for rsa_key.p8, rsa_key.pub, and output.txt")
	cmd.Flags().StringVarP(&opts.user, "user", "u", defaultUser, "Snowflake user in the ALTER USER statement")
	cmd.Flags().BoolVarP(&opts.generate, "generate", "g", false, "create a new PKCS#8 key pair")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "overwrite existing key files when generating")
	cmd.Flags().IntVarP(&opts.bits, "bits", "b", keys.MinBits, "RSA key size when generating")
	cmd.Flags().StringVarP(&opts.passphrase, "passphrase", "p", "", "encrypt a new private key, or decrypt an existing one")

	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &UsageError{Err: err}
	})

	_ = cmd.RegisterFlagCompletionFunc("dir", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveFilterDirs
	})
	_ = cmd.RegisterFlagCompletionFunc("bits", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"2048\tMinimum and default",
			"4096\tLarger modulus",
		}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("user", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("passphrase", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	})

	// A real subcommand makes Cobra register `help`. Disable the default
	// completion command so we do not get two of them.
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.AddCommand(newCompletionCommand(cmd))
	cmd.AddCommand(newTestCommand())

	return cmd
}

func newTestCommand() *cobra.Command {
	var (
		dir        string
		passphrase string
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Verify that rsa_key.p8 and rsa_key.pub are a matching pair",
		Long: `test reads rsa_key.p8 and rsa_key.pub and confirms the public key derived
from the private key matches the public key file, catching a mismatched or
stale rsa_key.pub. Pass --passphrase when the private key is encrypted.`,
		Example: `  # Check the pair in the current directory
  keypair-generator test

  # Check a pair in another directory
  keypair-generator test --dir ./keys`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return &UsageError{Err: err}
			}

			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTest(cmd, dir, passphrase)
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", ".", "directory containing rsa_key.p8 and rsa_key.pub")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "passphrase for an encrypted private key")

	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &UsageError{Err: err}
	})

	_ = cmd.RegisterFlagCompletionFunc("dir", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveFilterDirs
	})
	_ = cmd.RegisterFlagCompletionFunc("passphrase", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func runTest(cmd *cobra.Command, dirFlag, passphrase string) error {
	dir := filepath.Clean(dirFlag)
	privatePath := filepath.Join(dir, keys.PrivateFile)
	publicPath := filepath.Join(dir, keys.PublicFile)

	privatePEM, publicPEM, err := keys.ReadAndValidate(privatePath, publicPath, passphrase)
	if err != nil {
		return err
	}

	if err := keys.VerifyMatch(privatePEM, publicPEM, passphrase); err != nil {
		return err
	}

	return writeLine(cmd.OutOrStdout(), "OK: %s matches %s", publicPath, privatePath)
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate a shell completion script",
		Long: `Generate a completion script for the specified shell.

  source <(keypair-generator completion bash)
  source <(keypair-generator completion zsh)
  keypair-generator completion fish | source
`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs)(cmd, args); err != nil {
				return &UsageError{Err: err}
			}

			return nil
		},
		ValidArgs:    []string{"bash", "zsh", "fish", "powershell"},
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(cmd.OutOrStdout(), true)
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			default:
				return &UsageError{Err: fmt.Errorf("unknown shell %q", args[0])}
			}
		},
	}
}

// ExitCode maps a command error to a Unix exit status: 0 success, 2 usage, 1 otherwise.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	if _, ok := errors.AsType[*UsageError](err); ok {
		return 2
	}

	msg := err.Error()
	if strings.Contains(msg, "unknown command") {
		return 2
	}

	return 1
}

func run(cmd *cobra.Command, opts *options) error {
	dir := filepath.Clean(opts.dir)
	privatePath := filepath.Join(dir, keys.PrivateFile)
	publicPath := filepath.Join(dir, keys.PublicFile)

	if opts.generate {
		if err := keys.WriteNewPair(privatePath, publicPath, opts.bits, opts.force, opts.passphrase); err != nil {
			return err
		}

		if err := writeLine(cmd.ErrOrStderr(), "wrote %s", privatePath); err != nil {
			return err
		}

		if err := writeLine(cmd.ErrOrStderr(), "wrote %s", publicPath); err != nil {
			return err
		}
	}

	privatePEM, publicPEM, err := keys.ReadAndValidate(privatePath, publicPath, opts.passphrase)
	if err != nil {
		return err
	}

	if bytes.Contains(privatePEM, []byte("ENCRYPTED PRIVATE KEY")) {
		if err := writeLine(cmd.ErrOrStderr(), "private key is encrypted; the passphrase is not included in %s", keys.OutputFile); err != nil {
			return err
		}
	}

	body, err := keys.PEMBody(publicPEM)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	user := opts.user
	if user == "" {
		user = defaultUser
	}

	outputPath := filepath.Join(dir, keys.OutputFile)
	contents := fmt.Sprintf(
		"AWS secret key: SNOWFLAKE_PRIVATE_KEY_B64\n%s\n\nSnowflake:\nALTER USER %s SET RSA_PUBLIC_KEY='%s';\n",
		base64.StdEncoding.EncodeToString(privatePEM),
		user,
		body,
	)

	if err := os.WriteFile(outputPath, []byte(contents), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}

	if err := writeLine(cmd.ErrOrStderr(), "wrote %s", outputPath); err != nil {
		return err
	}

	if _, err := io.WriteString(cmd.OutOrStdout(), contents); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

func writeLine(w io.Writer, format string, args ...any) error {
	if _, err := fmt.Fprintf(w, format+"\n", args...); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}
