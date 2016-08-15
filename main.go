package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/rancher/secrets-api/command"
	"github.com/urfave/cli"
)

var VERSION = "v0.0.0-dev"

func beforeApp(c *cli.Context) error {
	if c.GlobalBool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "secrets-api"
	app.Version = VERSION
	app.Usage = "secrets api server"
	app.Before = beforeApp
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name: "debug,d",
		},
	}

	app.Commands = []cli.Command{
		command.ServerCommand(),
	}

	app.Run(os.Args)
}
