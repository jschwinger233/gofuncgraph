package symparser

import (
	"debug/elf"
	"sort"

	"github.com/jschwinger233/ufuncgraph/utils"
	"github.com/pkg/errors"
)

func (p *SymParser) FuncnamesMatchedWildcards(wildcards []string) (funcnames []string, err error) {
	symbols, _, err := p.ELF.Symbols()
	if err != nil {
		return
	}
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			for _, wc := range wildcards {
				if utils.MatchWildcard(wc, symbol.Name) {
					funcnames = append(funcnames, symbol.Name)
					break
				}
			}
		}
	}
	return
}

func (p *SymParser) FuncPcRangeInSymtab(name string) (lowpc, highpc uint64, err error) {
	symbols, symnames, err := p.ELF.Symbols()
	if err != nil {
		return
	}

	sym, ok := symnames[name]
	if !ok || elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
		err = errors.WithMessage(SymbolNotFoundError, name)
		return
	}

	idx := sort.Search(len(symbols), func(i int) bool { return symbols[i].Value > sym.Value })
	if idx < len(symbols) {
		highpc = symbols[idx].Value
	}

	lowpc = sym.Value
	return
}
