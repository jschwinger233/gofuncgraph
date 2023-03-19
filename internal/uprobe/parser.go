package uprobe

import (
	debugelf "debug/elf"

	"github.com/jschwinger233/gofuncgraph/elf"
)

type ParseOptions struct {
	Wildcards     []string
	ExWildcards   []string
	Fetch         map[string]map[string]string // funcname: varname: expression
	CustomOffsets map[string][]uint64          // funcname: [rel_offset]
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
		entOffset, err := elf.FuncOffset(funcname)
		if err != nil {
			return nil, err
		}
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
		for _, retOffset := range retOffsets {
			uprobes = append(uprobes, Uprobe{
				Funcname:  funcname,
				Location:  AtRet,
				AbsOffset: retOffset,
				RelOffset: retOffset - entOffset,
			})
		}
	}
	return
}
