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
				Name:    "backtrace",
				Aliases: []string{"b"},
				Value:   false,
				Usage:   "backtrace, show the stack chains",
			},
			&cli.IntFlag{
				Name:    "depth",
				Aliases: []string{"d"},
				Value:   0,
				Usage:   "uprobe search depth",
			},
			&cli.BoolFlag{
				Name:  "debug",
				Value: false,
				Usage: "enable debug logging",
			},
		},
		Before: func(c *cli.Context) error {
			if c.Bool("debug") {
				log.SetLevel(log.DebugLevel)
			}
			return nil
		},
		Action: func(ctx *cli.Context) (err error) {
			backtrace, depth := ctx.Bool("backtrace"), ctx.Int("depth")
			bin := ctx.Args().First()
			wildcards := ctx.Args().Tail()

			tracer, err := NewTracer(bin, wildcards, backtrace, depth)
			if err != nil {
				return
			}
			return tracer.Start()
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
