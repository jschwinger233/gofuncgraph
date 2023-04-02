package uprobe

import (
	debugelf "debug/elf"
	"errors"
	"fmt"

	"github.com/jschwinger233/gofuncgraph/elf"
	log "github.com/sirupsen/logrus"
)

type ParseOptions struct {
	Wildcards []string
	Fetch     map[string]map[string]string // funcname: varname: expression
}

func Parse(elf *elf.ELF, opts *ParseOptions) (uprobes []Uprobe, err error) {
	fetchArgs, err := parseFetchArgs(opts.Fetch)
	if err != nil {
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
		sym, err := elf.ResolveSymbol(funcname)
		if err != nil {
			return nil, err
		}
		entOffset, err := elf.FuncOffset(funcname)
		if err != nil {
			return nil, err
		}
		fmt.Printf("0x%x -> ", entOffset)
		uprobes = append(uprobes, Uprobe{
			Funcname:  funcname,
			Location:  AtEntry,
			Address:   sym.Value,
			AbsOffset: entOffset,
			RelOffset: 0,
			FetchArgs: fetchArgs[funcname],
		})

		retOffsets, err := elf.FuncRetOffsets(funcname)
		if err == nil && len(retOffsets) == 0 {
			err = errors.New("no ret offsets")
		}
		if err != nil {
			log.Warnf("skip %s, failed to get ret offsets: %v", funcname, err)
			uprobes = uprobes[:len(uprobes)-1]
			continue
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
