package command

import (
	"log"
	"os"
	"strconv"
	"syscall"
	"time"

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

	cattleParentID := os.Getenv("CATTLE_PARENT_PID")
	if cattleParentID != "" {
		if pid, err := strconv.Atoi(cattleParentID); err == nil {
			go func() {
				for {
					process, err := os.FindProcess(pid)
					if err != nil {
						log.Fatalf("Failed to find process: %s\n", err)
					} else {
						err := process.Signal(syscall.Signal(0))
						if err != nil {
							log.Fatal("Parent process went away. Shutting down.")
						}
					}
					time.Sleep(time.Millisecond * 250)
				}
			}()
		}
	}

	backends.SetBackendConfigs(backendConfig)

	return service.StartServer(c.String("listen-address"))
}
