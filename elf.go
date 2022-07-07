package main

import (
	"debug/dwarf"
	"debug/elf"

	myelf "github.com/jschwinger233/ufuncgraph/elf"
	"github.com/jschwinger233/ufuncgraph/utils"
	"golang.org/x/arch/x86/x86asm"
)

func ParseOffsets(binPath string, wildcards []string) (entryOffsets, exitOffsets []uint64, err error) {
	elfFile, err := myelf.New(binPath)
	if err != nil {
		return
	}

	pcs := map[string][2]uint64{}
	for debugInfo := range elfFile.IterDebugInfo() {
		if debugInfo.Tag == dwarf.TagSubprogram {
			v := debugInfo.Val(dwarf.AttrName)
			if v == nil {
				continue
			}
			name := v.(string)
			matched := false
			for _, wildcard := range wildcards {
				if utils.MatchWildcard(wildcard, name) {
					if _, ok := pcs[name]; ok {
						// golang's dwarf bug: duplicate function entries
						continue
					}
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			v = debugInfo.Val(dwarf.AttrLowpc)
			if v == nil {
				continue
			}
			lowpc := v.(uint64)
			v = debugInfo.Val(dwarf.AttrHighpc)
			if v == nil {
				continue
			}
			highpc := v.(uint64)
			pcs[name] = [2]uint64{lowpc, highpc}
		}
	}

	textSection := elfFile.Section(".text")
	textBytes, err := elfFile.SectionBytes(".text")
	if err != nil {
		return
	}

	for _, pc := range pcs {
		instructions := textBytes[pc[0]-textSection.Addr : pc[1]-textSection.Addr]
		offset := pc[0] - textSection.Addr + textSection.Offset
		bpCnt, foundEntry := 0, false
		for {
			inst, err := x86asm.Decode(instructions, 64)
			if err != nil {
				break
			}
			for _, a := range inst.Args {
				if a != nil && a.String() == "RBP" {
					bpCnt++
					if bpCnt == 2 {
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
	return
}

func ParseSymtab(binPath string) (_ []elf.Symbol, err error) {
	elfFile, err := myelf.New(binPath)
	if err != nil {
		return
	}

	return elfFile.Symbols()
}
