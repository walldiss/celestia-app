package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func initEnvCmd() *cobra.Command {
	var provider string

	cmd := &cobra.Command{
		Use:   "init-env",
		Short: "Generate a .env template file",
		Long:  "Generate a .env template file with the required environment variables for the specified cloud provider.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if provider == "" {
				provider = "digitalocean"
			}

			var envContent string

			switch provider {
			case "digitalocean":
				envContent = generateDigitalOceanEnv()
			case "googlecloud":
				envContent = generateGoogleCloudEnv()
			case "aws":
				envContent = generateAWSEnv()
			default:
				return fmt.Errorf("unknown provider %q (supported: digitalocean, googlecloud, aws)", provider)
			}

			// Check if .env already exists
			if _, err := os.Stat(".env"); err == nil {
				return fmt.Errorf(".env file already exists. Delete it first or edit manually")
			}

			// Write .env file
			if err := os.WriteFile(".env", []byte(envContent), 0o600); err != nil {
				return fmt.Errorf("failed to write .env file: %w", err)
			}

			fmt.Printf("✅ Created .env template for %s\n", provider)
			fmt.Println("\nNext steps:")
			fmt.Println("1. Edit .env and fill in your credentials")
			fmt.Println("2. Run: talis init -c <chain-id> -e <experiment> --with-observability --provider", provider)

			return nil
		},
	}

	cmd.Flags().StringVarP(&provider, "provider", "p", "digitalocean", "Cloud provider (digitalocean, googlecloud, aws)")

	return cmd
}

func generateDigitalOceanEnv() string {
	return `# Provider Configuration
PROVIDER=digitalocean

# DigitalOcean Configuration
# Get your API token from: https://cloud.digitalocean.com/account/api/tokens
DIGITALOCEAN_TOKEN=

# REQUIRED: path to your SSH PUBLIC key (must end in .pub). Talis uploads
# this key to the provider as the SSH key and bakes its contents into every
# instance's /root/.ssh/authorized_keys.
#
# Talis does NOT need the matching private key. SSH'ing in is delegated to
# the operator's local ssh client — make sure your default identity files
# (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.), ssh-agent, or ~/.ssh/config
# can present the matching private key. Quick fix:
#   ssh-add ~/.ssh/id_ed25519
# Or per-host:
#   Host *.compute.amazonaws.com 18.* 3.* 13.* 35.* 54.*
#     User root
#     IdentityFile ~/.ssh/id_ed25519
#     StrictHostKeyChecking no
TALIS_SSH_KEY_PATH=~/.ssh/id_ed25519.pub
TALIS_SSH_KEY_NAME=your-username

# DigitalOcean Spaces (optional - for payload distribution)
# Create a Space and generate API keys at: https://cloud.digitalocean.com/spaces
# DO_SPACES_REGION=fra1
# DO_SPACES_ACCESS_KEY_ID=
# DO_SPACES_SECRET_ACCESS_KEY=
# DO_SPACES_BUCKET=
# DO_SPACES_ENDPOINT=https://fra1.digitaloceanspaces.com
`
}

func generateGoogleCloudEnv() string {
	return `# Provider Configuration
PROVIDER=googlecloud

# Google Cloud Configuration
# Project ID from: https://console.cloud.google.com/
GOOGLE_CLOUD_PROJECT=

# Service account key JSON path
# Create at: https://console.cloud.google.com/iam-admin/serviceaccounts
# Download the JSON key file and set the path below
GOOGLE_CLOUD_KEY_JSON_PATH=

# REQUIRED: path to your SSH PUBLIC key (must end in .pub). Talis uploads
# this key to the provider as the SSH key and bakes its contents into every
# instance's /root/.ssh/authorized_keys.
#
# Talis does NOT need the matching private key. SSH'ing in is delegated to
# the operator's local ssh client — make sure your default identity files
# (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.), ssh-agent, or ~/.ssh/config
# can present the matching private key. Quick fix:
#   ssh-add ~/.ssh/id_ed25519
# Or per-host:
#   Host *.compute.amazonaws.com 18.* 3.* 13.* 35.* 54.*
#     User root
#     IdentityFile ~/.ssh/id_ed25519
#     StrictHostKeyChecking no
TALIS_SSH_KEY_PATH=~/.ssh/id_ed25519.pub
TALIS_SSH_KEY_NAME=your-username

# DigitalOcean Spaces (optional - for payload distribution)
# DO_SPACES_REGION=fra1
# DO_SPACES_ACCESS_KEY_ID=
# DO_SPACES_SECRET_ACCESS_KEY=
# DO_SPACES_BUCKET=
# DO_SPACES_ENDPOINT=https://fra1.digitaloceanspaces.com
`
}

func generateAWSEnv() string {
	return `# Provider Configuration
PROVIDER=aws

# AWS Credentials (used for both EC2 and the S3 payload bucket)
# Create an access key at: https://console.aws.amazon.com/iam/home#/security_credentials
# The user must have EC2 permissions (RunInstances, Terminate, Describe*,
# ImportKeyPair, CreateSecurityGroup/AuthorizeSecurityGroupIngress,
# CreatePlacementGroup, DescribeVpcs/DescribeSubnets, DescribeImages) and
# S3 (PutObject, GetObject) on the payload bucket.
#
# You can also leave these unset and use 'aws configure --profile <name>' +
# AWS_PROFILE=<name> — the Go SDK picks up shared credentials automatically.
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# Region for EC2 and (by default) the S3 payload bucket.
AWS_DEFAULT_REGION=us-east-1

# REQUIRED: path to your SSH PUBLIC key (must end in .pub). Talis uploads
# this key to AWS as the EC2 KeyPair and bakes its contents into every
# instance's /root/.ssh/authorized_keys.
#
# Talis does NOT need the matching private key. SSH'ing in is delegated to
# the operator's local ssh client — make sure your default identity files
# (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.), ssh-agent, or ~/.ssh/config
# can present the matching private key. Quick fix:
#   ssh-add ~/.ssh/id_ed25519
# Or per-host:
#   Host *.compute.amazonaws.com 18.* 3.* 13.* 35.* 54.*
#     User root
#     IdentityFile ~/.ssh/id_ed25519
#     StrictHostKeyChecking no
TALIS_SSH_KEY_PATH=~/.ssh/id_ed25519.pub
TALIS_SSH_KEY_NAME=your-username

# S3 Payload Bucket (optional — omit and use 'deploy --direct-payload-upload')
# Must be an S3 bucket you own in AWS_DEFAULT_REGION.
# AWS_S3_BUCKET=

# Cluster placement group: talis derives the PG name as
#   "talis-cluster-<chain-id>"
# at runtime, so each experiment gets its own PG and concurrent
# experiments don't collide on AZ. A PG is locked to the AZ of its first
# instance — sharing a single PG across experiments would force everyone
# into the same AZ even when one is short on capacity. Pick a unique
# --chainID (e.g. include your initials or a timestamp) when running
# alongside other tests in the same AWS account.
`
}
