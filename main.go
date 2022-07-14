//go:build linux
// +build linux

package main

import (
	"os"

	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func init() {
	// TODO: lift fileno rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	app := &cli.App{
		Name: "utrace",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "back",
				Aliases: []string{"b"},
				Value:   false,
				Usage:   "backtrace, show the stack rewinding",
			},
			&cli.BoolFlag{
				Name:    "funcgraph",
				Aliases: []string{"g"},
				Value:   false,
				Usage:   "show function graph",
			},
			&cli.IntFlag{
				Name:    "forward-depth",
				Aliases: []string{"d"},
				Value:   0,
				Usage:   "forwardtrace depth",
			},
			&cli.BoolFlag{
				Name:  "debug",
				Value: false,
				Usage: "enable debug logging",
			},
			&cli.BoolFlag{
				Name:  "golang",
				Value: false,
				Usage: "tracing golang process",
			},
		},
		Before: func(c *cli.Context) error {
			if c.Bool("debug") {
				log.SetLevel(log.DebugLevel)
			}
			return nil
		},
		Action: func(ctx *cli.Context) (err error) {
			back, funcgraph, depth := ctx.Bool("back"), ctx.Bool("funcgraph"), ctx.Int("forward-depth")
			golang := ctx.Bool("golang")
			bin := ctx.Args().First()
			funcWildcards := ctx.Args().Tail()

			tracer, err := NewTracer(golang, back, funcgraph, depth)
			if err != nil {
				return
			}
			if err = tracer.Attach(bin, funcWildcards); err != nil {
				return
			}
			return tracer.Tracing(bin)
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
