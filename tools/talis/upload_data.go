package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// uploadDataCmd creates a cobra command for kicking off trace collection
func uploadDataCmd() *cobra.Command {
	var rootDir string

	cmd := &cobra.Command{
		Use:     "upload-data",
		Short:   "Upload data from the talis network",
		Long:    "Connects to every node in the network and starts the upload_traces.sh script in a detached tmux session.",
		Aliases: []string{"u"},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(rootDir)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if len(cfg.Validators) == 0 {
				return fmt.Errorf("no validators (nodes) found in config")
			}

			const sessionName = "traces"
			return runScriptInTMux(
				cfg.Validators,
				"source /root/payload/upload_traces.sh",
				sessionName,
				time.Minute*5,
			)
		},
	}

	// define your flags
	cmd.Flags().StringVarP(&rootDir, "directory", "d", ".", "root directory containing your config")
	return cmd
}
