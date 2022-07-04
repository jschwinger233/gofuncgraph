package main

import (
	"fmt"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/jschwinger233/ufuncgraph/bpf"
)

type Symbol struct {
	Name   string
	Offset uint64
}

func PrintFuncgraph(ch <-chan bpf.UfuncgraphEvent, binPath string) (err error) {
	goroutine2events := map[uint64][]bpf.UfuncgraphEvent{}
	ip2sym := map[uint64]*Symbol{}
	for event := range ch {
		fmt.Printf("%+v\n", event)
		if event.Errno != 0 {
			return fmt.Errorf("event error: %d", event.Errno)
		}

		if _, ok := goroutine2events[event.Goid]; !ok {
			goroutine2events[event.Goid] = []bpf.UfuncgraphEvent{}
		}
		length := len(goroutine2events[event.Goid])
		if length == 0 && event.HookPoint == 1 {
			continue
		}
		if length > 0 && event.HookPoint == 0 && goroutine2events[event.Goid][length-1].HookPoint == 0 && goroutine2events[event.Goid][length-1].StackDepth == event.StackDepth {
			continue
		}
		goroutine2events[event.Goid] = append(goroutine2events[event.Goid], event)
		ip2sym[event.Ip] = &Symbol{Offset: 0xffffffffffffffff}
		ip2sym[event.CallerIp] = &Symbol{Offset: 0xffffffffffffffff}
	}

	syms, err := ParseSymtab(binPath)
	if err != nil {
		return
	}
	for _, sym := range syms {
		for ip, symbol := range ip2sym {
			if ip-sym.Value < symbol.Offset {
				symbol.Name = sym.Name
				symbol.Offset = ip - sym.Value
			}
		}
	}

	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime
	fmt.Printf("%s\n", bootTime)
	for _, events := range goroutine2events {
		println("-----------------")
		ident := ""
		for _, event := range events {
			t := bootTime.Add(time.Duration(event.TimeNs)).Format("2006-01-02 15:04:05.0000")
			if event.HookPoint == 0 {
				fmt.Printf("%s %s %s { %s+%d\n", t, ident, ip2sym[event.Ip].Name, ip2sym[event.CallerIp].Name, ip2sym[event.CallerIp].Offset)
				ident += "  "
			} else {
				if len(ident) == 0 {
					continue
				}
				ident = ident[:len(ident)-2]
				fmt.Printf("%s %s } %s+%d\n", t, ident, ip2sym[event.Ip].Name, ip2sym[event.Ip].Offset)
			}
		}
	}
	return
}
