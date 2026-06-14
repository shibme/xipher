package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"xipher.org/xipher/internal/kms"
)

func kmsCommand() *cobra.Command {
	if kmsCmd == nil {
		kmsCmd = &cobra.Command{
			Use:    "kms",
			Short:  "Run the Xipher Key Management Service (XKMS)",
			Hidden: true,
			Run: func(cmd *cobra.Command, args []string) {
				configPath, _ := cmd.Flags().GetString(kmsConfigFlag.name)
				if configPath == "" {
					exitOnError(fmt.Errorf("--%s is required", kmsConfigFlag.name), false)
				}
				if err := runKMS(configPath); err != nil {
					exitOnError(err, false)
				}
			},
		}
		kmsCmd.Flags().StringP(kmsConfigFlag.fields())
	}
	return kmsCmd
}

func runKMS(configPath string) error {
	cfg, err := kms.LoadConfig(configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := kms.NewServer(ctx, cfg)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "XKMS listening on %s:%d\n", cfg.Server.Host, cfg.Server.Port)
	return srv.Run(ctx)
}
