package main

import (
	"debug/elf"
	"fmt"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/jschwinger233/ufuncgraph/bpf"
)

type Symbol struct {
	Name   string
	Offset uint64
}

type Eventpool struct {
	goroutine2events map[uint64][]bpf.UfuncgraphEvent
	goroutine2stack  map[uint64]uint64
	bootTime         time.Time
}

func NewGevent() (_ *Eventpool, err error) {
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime
	return &Eventpool{
		goroutine2events: map[uint64][]bpf.UfuncgraphEvent{},
		goroutine2stack:  map[uint64]uint64{},
		bootTime:         bootTime,
	}, nil
}

func (p *Eventpool) Add(event bpf.UfuncgraphEvent) {
	length := len(p.goroutine2events[event.Goid])
	if length == 0 && event.HookPoint == 1 {
		return
	}
	if length > 0 && event.HookPoint == 0 && p.goroutine2events[event.Goid][length-1].HookPoint == 0 && p.goroutine2events[event.Goid][length-1].StackDepth == event.StackDepth {
		return
	}
	p.goroutine2events[event.Goid] = append(p.goroutine2events[event.Goid], event)
	p.goroutine2stack[event.Goid] = p.goroutine2stack[event.Goid] - 2*uint64(event.HookPoint) + 1
}

func (p *Eventpool) StackCompleted(goid uint64) bool {
	return p.goroutine2stack[goid] == 0
}

func (p *Eventpool) PrintStack(goid uint64, symInterp *SymInterp) {
	ident := ""
	println()
	for _, event := range p.goroutine2events[goid] {
		t := p.bootTime.Add(time.Duration(event.TimeNs)).Format("2006-01-02 15:04:05.0000")
		if event.HookPoint == 0 {
			fmt.Printf("%s %s %s { %s\n", t, ident, symInterp.Interp(event.Ip, withOffset(false)), symInterp.Interp(event.CallerIp, withOffset(true)))
			ident += "  "
		} else {
			if len(ident) == 0 {
				continue
			}
			ident = ident[:len(ident)-2]
			fmt.Printf("%s %s } %s\n", t, ident, symInterp.Interp(event.Ip, withOffset(true)))
		}
	}
	delete(p.goroutine2events, goid)
	return
}

type SymInterp struct {
	binPath string
	syms    []elf.Symbol
	cache   map[uint64]Symbol
}

type withOffset bool

func NewSymInterp(binPath string) (_ *SymInterp, err error) {
	syms, err := ParseSymtab(binPath)
	if err != nil {
		return
	}
	return &SymInterp{
		binPath: binPath,
		syms:    syms,
		cache:   map[uint64]Symbol{},
	}, nil
}

func (i *SymInterp) Interp(ip uint64, withOffset withOffset) string {
	if _, ok := i.cache[ip]; !ok {
		symbol := Symbol{Offset: 0xffffffffffffffff}
		for _, sym := range i.syms {
			if ip-sym.Value < symbol.Offset {
				symbol.Name = sym.Name
				symbol.Offset = ip - sym.Value
			}
		}
		i.cache[ip] = symbol
	}

	sym := i.cache[ip]
	if withOffset {
		return fmt.Sprintf("%s+%d", sym.Name, sym.Offset)
	}
	return sym.Name
}

func FuncgraphStream(ch <-chan bpf.UfuncgraphEvent, binPath string) (err error) {
	symInterp, err := NewSymInterp(binPath)
	if err != nil {
		return
	}

	pool, err := NewGevent()
	if err != nil {
		return
	}

	for event := range ch {
		if event.Errno != 0 {
			return fmt.Errorf("event error: %d", event.Errno)
		}

		pool.Add(event)
		if pool.StackCompleted(event.Goid) {
			pool.PrintStack(event.Goid, symInterp)
		}
	}

	fmt.Printf("completed, detaching uprobes\n")
	return
}
