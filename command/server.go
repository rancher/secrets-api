package command

import (
	"github.com/rancher/secrets-api/service"
	"github.com/urfave/cli"
)

func ServerCommand() cli.Command {
	return cli.Command{
		Name:   "server",
		Usage:  "Start the Secrets API Server",
		Action: startServer,
	}
}

func startServer(c *cli.Context) error {
	return service.StartServer()
}
