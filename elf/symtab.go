package elf

import (
	"debug/elf"
	"fmt"
	"sort"

	"github.com/pkg/errors"
)

func (e *ELF) Symbols() (symbols []elf.Symbol, symnames map[string]elf.Symbol, err error) {
	if _, ok := e.cache["symbols"]; ok {
		return e.cache["symbols"].([]elf.Symbol), e.cache["symnames"].(map[string]elf.Symbol), nil
	}

	if symbols, err = e.elfFile.Symbols(); err != nil {
		return
	}

	sort.Slice(symbols, func(i, j int) bool { return symbols[i].Value < symbols[j].Value })

	symnames = map[string]elf.Symbol{}
	for _, symbol := range symbols {
		symnames[symbol.Name] = symbol
	}
	e.cache["symbols"] = symbols
	e.cache["symnames"] = symnames
	return
}

func (e *ELF) ResolveAddress(addr uint64) (syms []elf.Symbol, offset uint, err error) {
	if addr == 0 {
		err = errors.Wrapf(SymbolNotFoundError, "0")
		return
	}
	symbols, _, err := e.Symbols()
	if err != nil {
		return
	}

	idx := sort.Search(len(symbols), func(i int) bool { return symbols[i].Value > addr })
	if idx == 0 {
		err = errors.Wrap(SymbolNotFoundError, fmt.Sprintf("%x", addr))
		return
	}

	sym := symbols[idx-1]
	for i := idx - 1; i >= 0 && symbols[i].Value == sym.Value; i-- {
		syms = append(syms, symbols[i])
	}
	for i := idx; i < len(symbols) && symbols[i].Value == sym.Value; i++ {
		syms = append(syms, symbols[i])
	}
	return syms, uint(addr - sym.Value), nil
}

func (e *ELF) ResolveSymbol(sym string) (symbol elf.Symbol, err error) {
	_, symnames, err := e.Symbols()
	if err != nil {
		return
	}

	symbol, ok := symnames[sym]
	if !ok {
		err = errors.Wrap(SymbolNotFoundError, sym)
	}
	return
}

func (e *ELF) FuncOffset(name string) (offset uint64, err error) {
	sym, err := e.ResolveSymbol(name)
	if err != nil {
		return
	}
	section := e.Section(".text")
	return sym.Value - section.Addr + section.Offset, nil
}

func (e *ELF) FuncPcRangeInSymtab(name string) (lowpc, highpc uint64, err error) {
	symbols, symnames, err := e.Symbols()
	if err != nil {
		return
	}

	sym, ok := symnames[name]
	if !ok || elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
		err = errors.Wrap(SymbolNotFoundError, name)
		return
	}

	idx := sort.Search(len(symbols), func(i int) bool { return symbols[i].Value > sym.Value })
	if idx < len(symbols) {
		highpc = symbols[idx].Value
	}

	lowpc = sym.Value
	return
}
