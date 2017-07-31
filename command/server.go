package command

import (
	"github.com/rancher/secrets-api/backends"
	"github.com/rancher/secrets-api/service"
	"github.com/urfave/cli"
)

func ServerCommand() cli.Command {
	return cli.Command{
		Name:   "server",
		Usage:  "Start the Secrets API Server",
		Action: startServer,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:   "enc-key-path",
				Usage:  "Encryption key file to use for localkey encryption",
				EnvVar: "ENC_KEY_PATH",
			},
			cli.StringFlag{
				Name:   "vault-url",
				Usage:  "URL For Vault server with Transit backend enabled",
				EnvVar: "VAULT_ADDR",
			},
			cli.StringFlag{
				Name:   "vault-token",
				Usage:  "URL For Vault server with Transit backend enabled",
				EnvVar: "VAULT_TOKEN",
			},
			cli.StringFlag{
				Name:   "listen-address",
				Usage:  "Address to listen on",
				Value:  "127.0.0.1:8181",
				EnvVar: "SECRETS_API_LISTEN_ADDRESS",
			},
		},
	}
}

func startServer(c *cli.Context) error {
	backendConfig := backends.NewConfig()

	backendConfig.EncryptionKeyPath = c.String("enc-key-path")
	backendConfig.VaultURL = c.String("vault-url")
	backendConfig.VaultToken = c.String("vault-token")
	backends.SetBackendConfigs(backendConfig)

	return service.StartServer(c.String("listen-address"))
}
