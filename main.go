//go:build linux
// +build linux

package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-sysinfo"
	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"golang.org/x/arch/x86/x86asm"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native -type event ufuncgraph ./ufuncgraph.c -- -I./headers

type Symbol struct {
	Name   string
	Offset uint64
}

func main() {
	binPath := os.Args[1]
	patterns := os.Args[2:]

	entryOffsets := []uint64{}
	exitOffsets := []uint64{}
	for _, pattern := range patterns {
		enters, exits, err := parseBinary(binPath, pattern)
		if err != nil {
			log.Fatal(err)
		}
		entryOffsets = append(entryOffsets, enters...)
		exitOffsets = append(exitOffsets, exits...)
	}
	fmt.Printf("entry %d, exit %d\n", len(entryOffsets), len(exitOffsets))

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := ufuncgraphObjects{}
	if err := loadUfuncgraphObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	for _, offset := range entryOffsets {

		uprobe, err := ex.Uprobe("", objs.OnEntry, &link.UprobeOptions{Offset: offset})
		if err != nil {
			log.Fatalf("creating uprobe: %s", err)
		}
		defer uprobe.Close()
	}
	for _, offset := range exitOffsets {
		uprobe, err := ex.Uprobe("", objs.OnExit, &link.UprobeOptions{Offset: offset})
		if err != nil {
			log.Fatalf("creating uprobe: %s", err)
		}
		defer uprobe.Close()
	}

	println("created uprobe")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	goroutines := map[uint64][]ufuncgraphEvent{}
	ips := map[uint64]*Symbol{}
Outer:
	for {
		event := ufuncgraphEvent{}
		select {
		case <-stopper:
			break Outer
		default:
			if err := objs.EventQueue.LookupAndDelete(nil, &event); err != nil {
				time.Sleep(time.Millisecond)
				continue
			}
			fmt.Printf("%+v\n", event)
			if event.Errno != 0 {
				log.Fatalf("error: %d", event.Errno)
			}

			if _, ok := goroutines[event.Goid]; !ok {
				goroutines[event.Goid] = []ufuncgraphEvent{}
			}
			length := len(goroutines[event.Goid])
			if length == 0 && event.HookPoint == 1 {
				continue
			}
			if length > 0 && event.HookPoint == 0 && goroutines[event.Goid][length-1].HookPoint == 0 && goroutines[event.Goid][length-1].StackDepth == event.StackDepth {
				continue
			}
			goroutines[event.Goid] = append(goroutines[event.Goid], event)
			ips[event.Ip] = &Symbol{Offset: 0xffffffffffffffff}
			ips[event.CallerIp] = &Symbol{Offset: 0xffffffffffffffff}
		}
	}

	post_process(binPath, goroutines, ips)
}

func post_process(binary string, goroutines map[uint64][]ufuncgraphEvent, ips map[uint64]*Symbol) {
	r, err := os.Open(binary)
	if err != nil {
		log.Fatal(err)
	}
	f, err := elf.NewFile(r)
	if err != nil {
		log.Fatal(err)
	}
	syms, err := f.Symbols()
	if err != nil {
		log.Fatal(err)
	}
	for _, sym := range syms {
		for ip, symbol := range ips {
			if ip-sym.Value < symbol.Offset {
				symbol.Name = sym.Name
				symbol.Offset = ip - sym.Value
			}
		}
	}

	host, err := sysinfo.Host()
	if err != nil {
		log.Fatal(err)
	}
	bootTime := host.Info().BootTime
	fmt.Printf("%s\n", bootTime)
	for _, events := range goroutines {
		println("-----------------")
		ident := ""
		for _, event := range events {
			t := bootTime.Add(time.Duration(event.TimeNs)).Format("2006-01-02 15:04:05.0000")
			if event.HookPoint == 0 {
				fmt.Printf("%s %s %s { %s+%d\n", t, ident, ips[event.Ip].Name, ips[event.CallerIp].Name, ips[event.CallerIp].Offset)
				ident += "  "
			} else {
				if len(ident) == 0 {
					continue
				}
				ident = ident[:len(ident)-2]
				fmt.Printf("%s %s } %s+%d\n", t, ident, ips[event.Ip].Name, ips[event.Ip].Offset)
			}
		}
	}
}

func parseBinary(binPath string, pattern string) (entry []uint64, exit []uint64, err error) {
	r, err := os.Open(binPath)
	if err != nil {
		return nil, nil, err
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, nil, err
	}
	abbrev, err := godwarf.GetDebugSectionElf(f, "abbrev")
	if err != nil {
		return nil, nil, err
	}
	frame, err := godwarf.GetDebugSectionElf(f, "frame")
	if err != nil {
		return nil, nil, err
	}
	info, err := godwarf.GetDebugSectionElf(f, "info")
	if err != nil {
		return nil, nil, err
	}
	line, err := godwarf.GetDebugSectionElf(f, "line")
	if err != nil {
		return nil, nil, err
	}
	ranges, err := godwarf.GetDebugSectionElf(f, "ranges")
	if err != nil {
		return nil, nil, err
	}

	dwarfData, err := dwarf.New(abbrev, nil, frame, info, line, nil, ranges, nil)
	if err != nil {
		return nil, nil, err
	}

	infoReader := dwarfData.Reader()
	pcs := map[string][2]uint64{}
	pattern = fmt.Sprintf("^%s$", pattern)
	for {
		entry, err := infoReader.Next()
		if err != nil {
			return nil, nil, err
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagSubprogram {
			v := entry.Val(dwarf.AttrName)
			if v == nil {
				continue
			}
			name := v.(string)
			matched, err := regexp.MatchString(pattern, name)
			if err != nil {
				return nil, nil, err
			}
			if matched {
				v = entry.Val(dwarf.AttrLowpc)
				if v == nil {
					continue
				}
				lowpc := v.(uint64)
				v = entry.Val(dwarf.AttrHighpc)
				if v == nil {
					continue
				}
				highpc := v.(uint64)
				pcs[name] = [2]uint64{lowpc, highpc}
			}
		}
	}
	fmt.Printf("%+v\n", pcs)
	entryOffsets := []uint64{}
	exitOffsets := []uint64{}
	textSection := f.Section(".text")
	binFile, err := os.Open(binPath)
	if err != nil {
		log.Fatal(err)
	}
	textBytes := make([]byte, textSection.Size)
	_, err = binFile.ReadAt(textBytes, int64(textSection.Offset))
	if err != nil {
		log.Fatal(err)
	}
	for _, pc := range pcs {
		instructions := textBytes[pc[0]-textSection.Addr : pc[1]-textSection.Addr]
		offset := pc[0] - textSection.Addr + textSection.Offset
		cnt, foundEntry := 0, false
		for {
			inst, err := x86asm.Decode(instructions, 64)
			if err != nil {
				break
			}
			for _, a := range inst.Args {
				if a != nil && a.String() == "RBP" {
					cnt++
					if cnt == 2 {
						entryOffsets = append(entryOffsets, offset+uint64(inst.Len))
						foundEntry = true
					}
				}
			}
			if inst.Op == x86asm.RET && foundEntry {
				exitOffsets = append(exitOffsets, offset)
			}
			offset += uint64(inst.Len)
			instructions = instructions[inst.Len:]
		}

	}
	return entryOffsets, exitOffsets, nil
}
