package elf

import "debug/elf"

func (f *ELFFile) Symbols() ([]elf.Symbol, error) {
	return f.elfFile.Symbols()
}
