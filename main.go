//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/jschwinger233/ufuncgraph/version"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

func init() {
	rlimit := syscall.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		log.Fatal(err)
	}
	rlimit = syscall.Rlimit{
		Cur: 1048576,
		Max: 1048576,
	}
	if err := syscall.Setrlimit(unix.RLIMIT_NOFILE, &rlimit); err != nil {
		log.Fatal(err)
	}
}

func main() {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Print(version.String())
	}

	app := &cli.App{
		Name: "ufuncgraph",
		// TODO@zc: kernel version
		Usage: "bpf(2)-based ftrace(1)-like function graph tracer for userspace! \n(only non-stripped static-linking Golang on x86-64 little-endian Linux is supported for now)",
		UsageText: `example: trace a specific function in etcd client "go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire"
  ufuncgraph ./bin 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire'

example: trace all functions in etcd client
  ufuncgraph ./bin 'go.etcd.io/etcd/client/v3/*'

example: trace a specific function and its downstream functions within 3 layers, but exclude the golang builtins
  ufuncgraph --depth 3 ./bin 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' '!runtime.*'

example: trace a specific function with some arguemnts and backtrace
  ufuncgraph --backtrace ./bin 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire(pfx=+0(+8(%rax)):c128, n_pfx=+16(%ax):u64, myKey=+0(+24(%rax)):c128)'
 `,
		Version: version.VERSION,
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
			args := ctx.Args().Tail()

			if bin == "" || ctx.Bool("help") {
				return cli.ShowAppHelp(ctx)
			}

			tracer, err := NewTracer(bin, args, backtrace, depth)
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
