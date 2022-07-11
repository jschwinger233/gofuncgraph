package symparser

import (
	"debug/elf"
	"fmt"
	"sort"

	"github.com/jschwinger233/ufuncgraph/utils"
	"github.com/pkg/errors"
)

func (p *SymParser) findMatchedFunctions(wildcards []string) (syms []string, err error) {
	symaddrs, _, err := p.getSymtab()
	if err != nil {
		return
	}
	for _, sym := range symaddrs {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
			for _, wc := range wildcards {
				if utils.MatchWildcard(wc, sym.Name) {
					syms = append(syms, sym.Name)
					break
				}
			}
		}
	}
	return
}

func (p *SymParser) addrToSymbol(addr uint64) (sym string, err error) {
	symaddrs, _, err := p.getSymtab()
	if err != nil {
		return
	}

	symbol, ok := symaddrs[addr]
	if !ok {
		err = fmt.Errorf("symbol not found: %x", addr)
		return
	}
	return symbol.Name, nil
}

func (p *SymParser) getSymtab() (symaddrs map[uint64]elf.Symbol, symnames map[string]elf.Symbol, err error) {
	if _, ok := p.cache["symaddrs"]; ok {
		return p.cache["symaddrs"].(map[uint64]elf.Symbol), p.cache["symnames"].(map[string]elf.Symbol), nil
	}

	symbols, err := p.elfFile.Symbols()
	if err != nil {
		return
	}

	sort.Slice(symbols, func(i, j int) bool { return symbols[i].Value < symbols[j].Value })

	symaddrs = map[uint64]elf.Symbol{}
	symnames = map[string]elf.Symbol{}
	for i, sym := range symbols {
		if i+1 < len(symbols) {
			sym.Size = uint64(symbols[i+1].Value - sym.Value)
		}
		symaddrs[sym.Value] = sym
		symnames[sym.Name] = sym
	}
	p.cache["symaddrs"] = symaddrs
	p.cache["symnames"] = symnames
	return
}

func (p *SymParser) findFuncRangeBySymtab(name string) (lowpc, highpc uint64, err error) {
	_, symnames, err := p.getSymtab()
	if err != nil {
		return
	}

	sym, ok := symnames[name]
	if !ok || elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
		err = errors.WithMessage(SymbolNotFoundError, name)
		return
	}

	lowpc = sym.Value
	highpc = sym.Value + sym.Size
	return
}
