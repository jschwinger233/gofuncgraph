package uprobe

import (
	debugelf "debug/elf"
	"fmt"

	"github.com/jschwinger233/gofuncgraph/elf"
)

type ParseOptions struct {
	Wildcards   []string
	ExWildcards []string
	Fetch       map[string]map[string]string // funcname: varname: expression
}

func Parse(elf *elf.ELF, opts *ParseOptions) (uprobes []Uprobe, err error) {
	if _, err = parseFetchArgs(opts.Fetch); err != nil {
		return
	}

	symbols, _, err := elf.Symbols()
	if err != nil {
		return
	}

	funcnames := []string{}
	for _, symbol := range symbols {
		if debugelf.ST_TYPE(symbol.Info) == debugelf.STT_FUNC {
			for _, wc := range opts.Wildcards {
				if MatchWildcard(wc, symbol.Name) {
					funcnames = append(funcnames, symbol.Name)
					break
				}
			}
		}
	}

	for _, funcname := range funcnames {
		fmt.Printf("add uprobes for %s: ", funcname)
		entOffset, err := elf.FuncOffset(funcname)
		if err != nil {
			return nil, err
		}
		fmt.Printf("0x%x -> ", entOffset)
		uprobes = append(uprobes, Uprobe{
			Funcname:  funcname,
			Location:  AtEntry,
			AbsOffset: entOffset,
			RelOffset: 0,
		})

		retOffsets, err := elf.FuncRetOffsets(funcname)
		if err != nil {
			return nil, err
		}
		fmt.Printf("[ ")
		for _, retOffset := range retOffsets {
			fmt.Printf("0x%x ", retOffset)
			uprobes = append(uprobes, Uprobe{
				Funcname:  funcname,
				Location:  AtRet,
				AbsOffset: retOffset,
				RelOffset: retOffset - entOffset,
			})
		}
		fmt.Printf("]\n")
	}
	return
}
