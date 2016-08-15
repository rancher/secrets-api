package command

import (
	"github.com/urfave/cli"
)

func ServerCommand() cli.Command {
	return cli.Command{
		Name:   "server",
		Usage:  "Start the Secrets API Server",
		Action: startServer,
	}
}

func startServer(c *cli.Command) error {
	return nil
}
