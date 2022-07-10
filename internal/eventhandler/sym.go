package eventhandler

import (
	"debug/elf"
	"fmt"

	myelf "github.com/jschwinger233/ufuncgraph/elf"
)

type Symbol struct {
	Name   string
	Offset uint64
}

type SymInterp struct {
	bin   string
	syms  []elf.Symbol
	cache map[uint64]Symbol
}

type withOffset bool

func NewSymInterp(bin string) (_ *SymInterp, err error) {
	elfFile, err := myelf.New(bin)
	if err != nil {
		return
	}
	syms, err := elfFile.Symbols()
	return &SymInterp{
		bin:   bin,
		syms:  syms,
		cache: map[uint64]Symbol{},
	}, err
}

func (i *SymInterp) Interp(ip uint64, withOffset withOffset) string {
	if _, ok := i.cache[ip]; !ok {
		symbol := Symbol{Offset: 0xffffffffffffffff}
		for _, sym := range i.syms {
			if ip-sym.Value < symbol.Offset {
				symbol.Name = sym.Name
				symbol.Offset = ip - sym.Value
			}
		}
		i.cache[ip] = symbol
	}

	sym := i.cache[ip]
	if withOffset {
		return fmt.Sprintf("%s+%d", sym.Name, sym.Offset)
	}
	return sym.Name
}
