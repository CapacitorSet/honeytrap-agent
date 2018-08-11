package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	cli "gopkg.in/urfave/cli.v1"

	logging "github.com/op/go-logging"

	"github.com/honeytrap/honeytrap-agent/server"

	_ "net/http/pprof"
)

var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
	{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
	{{end}}{{if .Flags}}
FLAGS:
	{{range .Flags}}{{.}}
	{{end}}{{end}}
VERSION:
` + server.Version +
	`{{ "\n"}}`

var log = logging.MustGetLogger("honeytrap-agent")

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func serve(c *cli.Context) error {
	options := []server.OptionFn{}

	v := c.GlobalString("server")
	if v == "" {
		return cli.NewExitError(fmt.Errorf(color.RedString("No target server set.")), 1)
	}
	options = append(options, server.WithServer(v))

	key := c.GlobalString("remote-key")
	if key == "" {
		return cli.NewExitError(fmt.Errorf(color.RedString("No remote key set.")), 1)
	}
	options = append(options, server.WithKey(key))

	name := c.GlobalString("name")
	if name == "" {
		return cli.NewExitError(fmt.Errorf(color.RedString("No name set.")), 1)
	}
	options = append(options, server.WithName(name))

	d := c.String("data")
	if d == "" {
		return cli.NewExitError(fmt.Errorf(color.RedString("No data dir set.")), 1)
	}
	if fn, err := server.WithDataDir(d); err != nil {
		return cli.NewExitError(err.Error(), 1)
	} else {
		options = append(options, fn)
	}

	options = append(options, server.WithToken())

	srvr, err := server.New(
		options...,
	)

	if err != nil {
		ec := cli.NewExitError(err.Error(), 1)
		return ec
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s := make(chan os.Signal, 1)
		signal.Notify(s, os.Interrupt)
		signal.Notify(s, syscall.SIGTERM)

		select {
		case <-s:
			cancel()
		}
	}()

	srvr.Run(ctx)
	return nil
}

func loadConfig(c *cli.Context) error {
	s := c.String("config")

	if s == "" {
		return nil
	}

	r, err := os.Open(s)
	if err != nil {
		ec := cli.NewExitError(fmt.Errorf(color.RedString("Could not open config file: %s", err.Error())), 1)
		return ec
	}

	defer r.Close()

	config := struct {
		Server    string `toml:"server"`
		RemoteKey string `toml:"remote-key"`
		DataDir   string `toml:"data-dir"`
		Name      string `toml:"name"`
	}{}

	if _, err := toml.DecodeReader(r, &config); err != nil {
		ec := cli.NewExitError(fmt.Errorf(color.RedString("Could not parse config file: %s", err.Error())), 1)
		return ec
	}

	c.Set("server", config.Server)
	c.Set("remote-key", config.RemoteKey)
	c.Set("data", config.DataDir)
	c.Set("name", config.Name)

	return nil
}

func New() *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Fprintf(c.App.Writer,
			`Version: %s
Release-Tag: %s
Commit-ID: %s
`, color.YellowString(server.Version), color.YellowString(server.ReleaseTag), color.YellowString(server.CommitID))
	}

	app := cli.NewApp()
	app.Name = "honeytrap-agent"
	app.Usage = "Honeytrap Agent"
	app.Commands = []cli.Command{}

	app.Before = loadConfig

	app.Action = serve

	app.Flags = append(app.Flags,
		cli.StringFlag{
			Name:  "config, f",
			Usage: "configuration from `FILE`",
		},
		cli.StringFlag{
			Name:  "server, s",
			Value: "",
			Usage: "server address",
		},
		cli.StringFlag{
			Name:  "remote-key, k",
			Value: "",
			Usage: "remote key of server",
		},
		cli.StringFlag{
			Name:  "data, d",
			Value: "~/.honeytrap-agent",
			Usage: "Store data in `DIR`",
		},
		cli.StringFlag{
			Name:  "name, n",
			Usage: "agent name",
		},
	)

	return app
}
