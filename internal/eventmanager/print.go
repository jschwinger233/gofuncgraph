package eventmanager

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/jschwinger233/ufuncgraph/internal/bpf"
)

func (p *EventManager) SprintCallChain(event bpf.UfuncgraphEvent) (chain string, err error) {
	calls := []string{}
	sym, off, err := p.elf.ResolveAddress(event.CallerIp)
	if err != nil {
		return
	}
	calls = append(calls, fmt.Sprintf("%s+%d", sym.Name, off))
	offset := 0
	for {
		ip := binary.LittleEndian.Uint64(event.Bt[offset : offset+8])
		if ip == 0 {
			break
		}
		offset += 8
		if offset >= len(event.Bt) {
			break
		}
		sym, off, err := p.elf.ResolveAddress(ip)
		if err != nil {
			return "", err
		}
		calls = append(calls, fmt.Sprintf("%s+%d", sym.Name, off))
	}
	return strings.Join(calls, " > "), nil
}

func (p *EventManager) PrintStack(StackId uint64) (err error) {
	indent := ""
	fmt.Println()
	for _, event := range p.goroutine2events[StackId] {
		t := p.bootTime.Add(time.Duration(event.TimeNs)).Format("2006-01-02 15:04:05.0000")
		sym, offset, err := p.elf.ResolveAddress(event.Ip)
		if err != nil {
			return err
		}
		if event.Location == 0 {
			callChain, err := p.SprintCallChain(event)
			if err != nil {
				return err
			}
			uprobe, err := p.GetUprobe(event)
			if err != nil {
				return err
			}
			if len(uprobe.FetchArgs) == 0 {
				fmt.Printf("%s %s %s { %s\n", t, indent, sym.Name, callChain)
			} else {
				args := []string{}
				data := event.Data[:]
				for _, arg := range uprobe.FetchArgs {
					args = append(args, arg.Sprint(data))
					data = data[arg.Size:]
				}
				fmt.Printf("%s %s %s(%s) { %s\n", t, indent, sym.Name, strings.Join(args, ", "), callChain)
			}
			indent += "  "
		} else {
			if len(indent) == 0 {
				continue
			}
			indent = indent[:len(indent)-2]
			fmt.Printf("%s %s } %s+%d\n", t, indent, sym.Name, offset)
		}
	}
	return
}

func (g *EventManager) PrintRemaining() {
	for StackId := range g.goroutine2events {
		g.PrintStack(StackId)
	}
}
