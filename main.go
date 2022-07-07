//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	help := flag.BoolP("help", "h", false, "print help")
	flag.Parse()
	if *help || len(flag.Args()) < 2 {
		fmt.Println("Usage: ufuncgraph <executable> <wildcard> [<wildcard>...]")
		return
	}
	binPath := flag.Arg(0)
	patterns := flag.Args()[1:]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tracer := Functracer{}
	if err := tracer.LoadBPF(); err != nil {
		log.Fatal(err)
	}
	if err := tracer.AttachUprobes(binPath, patterns); err != nil {
		log.Fatal(err)
	}
	defer tracer.DetachUprobes()
	if err := tracer.CollectEvents(ctx); err != nil {
		log.Fatal(err)
	}
}
