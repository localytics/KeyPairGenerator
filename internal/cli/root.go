// Package cli implements the keypair-generator Cobra command tree.
package cli

import (
	"errors"
	"fmt"
	"io"
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

type options struct {
	dir      string
	generate bool
	force    bool
	bits     int
}

// New returns a fresh command tree. Callers must not reuse the same
// command across Execute calls; Cobra accumulates flag state.
func New() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "keypair-generator",
		Short: "Generate or print Snowflake RSA key-pair values",
		Long: `keypair-generator creates or reads an unencrypted PKCS#8 RSA key pair and prints
the AWS secret and Snowflake ALTER USER values.

Every run reads rsa_key.p8 and rsa_key.pub, then prints:

  1. SNOWFLAKE_PRIVATE_KEY_B64 — Base64 of the private key DER (starts with MIIE). Store this as the AWS secret.
  2. A Snowflake ALTER USER statement with the public key body (no PEM headers).

Missing key files are an error unless --generate is also set. Encrypted private keys are rejected.`,
		Example: `  # Create a new key pair in the current directory
  keypair-generator --generate

  # Write keys to another directory
  keypair-generator --dir ./keys --generate

  # Replace an existing pair with a 4096-bit key
  keypair-generator --generate --force --bits 4096

  # Print values from keys that already exist
  keypair-generator`,
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

	cmd.Flags().StringVarP(&opts.dir, "dir", "d", ".", "directory for rsa_key.p8 and rsa_key.pub")
	cmd.Flags().BoolVarP(&opts.generate, "generate", "g", false, "create a new unencrypted PKCS#8 key pair")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "overwrite existing key files when generating")
	cmd.Flags().IntVarP(&opts.bits, "bits", "b", keys.MinBits, "RSA key size when generating")

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

	// A real subcommand makes Cobra register `help`. Disable the default
	// completion command so we do not get two of them.
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.AddCommand(newCompletionCommand(cmd))

	return cmd
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
		if err := keys.WriteNewPair(privatePath, publicPath, opts.bits, opts.force); err != nil {
			return err
		}

		if err := writeLine(cmd.ErrOrStderr(), "wrote %s", privatePath); err != nil {
			return err
		}

		if err := writeLine(cmd.ErrOrStderr(), "wrote %s", publicPath); err != nil {
			return err
		}
	}

	privatePEM, publicPEM, err := keys.ReadAndValidate(privatePath, publicPath)
	if err != nil {
		return err
	}

	privateBody, err := keys.PEMBody(privatePEM)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}

	body, err := keys.PEMBody(publicPEM)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	out := cmd.OutOrStdout()
	if err := writeLine(out, "AWS secret key: SNOWFLAKE_PRIVATE_KEY_B64"); err != nil {
		return err
	}

	if err := writeLine(out, "%s", privateBody); err != nil {
		return err
	}

	if err := writeLine(out, ""); err != nil {
		return err
	}

	if err := writeLine(out, "Snowflake:"); err != nil {
		return err
	}

	return writeLine(out, "ALTER USER {?user?} SET RSA_PUBLIC_KEY='%s';", body)
}

func writeLine(w io.Writer, format string, args ...any) error {
	if _, err := fmt.Fprintf(w, format+"\n", args...); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}
