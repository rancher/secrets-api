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
				Usage:  "Encryption key to use for localkey encryption",
				EnvVar: "ENC_KEY_PATH",
			},
		},
	}
}

func startServer(c *cli.Context) error {
	backendConfig := backends.NewConfig()
	backendConfig.EncryptionKeyPath = c.String("enc-key-path")
	backends.SetBackendConfigs(backendConfig)

	return service.StartServer()
}
