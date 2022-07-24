package elf

import (
	"debug/elf"
	"fmt"
	"sort"

	"github.com/pkg/errors"
)

func (f *ELF) Symbols() (symbols []elf.Symbol, symnames map[string]elf.Symbol, err error) {
	if _, ok := f.cache["symbols"]; ok {
		return f.cache["symbols"].([]elf.Symbol), f.cache["symnames"].(map[string]elf.Symbol), nil
	}

	if symbols, err = f.elfFile.Symbols(); err != nil {
		return
	}

	sort.Slice(symbols, func(i, j int) bool { return symbols[i].Value < symbols[j].Value })

	symnames = map[string]elf.Symbol{}
	for _, symbol := range symbols {
		symnames[symbol.Name] = symbol
	}
	f.cache["symbols"] = symbols
	f.cache["symnames"] = symnames
	return
}

func (f *ELF) ResolveAddress(addr uint64) (sym elf.Symbol, offset uint, err error) {
	symbols, _, err := f.Symbols()
	if err != nil {
		return
	}

	idx := sort.Search(len(symbols), func(i int) bool { return symbols[i].Value > addr })
	if idx == 0 {
		err = errors.WithMessage(SymbolNotFoundError, fmt.Sprintf("%x", addr))
		return
	}

	sym = symbols[idx-1]
	return sym, uint(addr - sym.Value), nil
}

func (f *ELF) ResolveSymbol(sym string) (symbol elf.Symbol, err error) {
	_, symnames, err := f.Symbols()
	if err != nil {
		return
	}

	symbol, ok := symnames[sym]
	if !ok {
		err = errors.WithMessage(SymbolNotFoundError, sym)
	}
	return
}

func (e *ELF) FuncPcRangeInSymtab(name string) (lowpc, highpc uint64, err error) {
	symbols, symnames, err := e.Symbols()
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
