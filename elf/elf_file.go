package elf

import (
	"debug/dwarf"
	"debug/elf"
	"os"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
)

type ELFFile struct {
	binPath   string
	binFile   *os.File
	elfFile   *elf.File
	dwarfData *dwarf.Data
}

func New(binPath string) (_ *ELFFile, err error) {
	binFile, err := os.Open(binPath)
	if err != nil {
		return
	}
	elfFile, err := elf.NewFile(binFile)
	if err != nil {
		return
	}
	abbrev, err := godwarf.GetDebugSectionElf(elfFile, "abbrev")
	if err != nil {
		return
	}
	frame, err := godwarf.GetDebugSectionElf(elfFile, "frame")
	if err != nil {
		return
	}
	info, err := godwarf.GetDebugSectionElf(elfFile, "info")
	if err != nil {
		return
	}
	line, err := godwarf.GetDebugSectionElf(elfFile, "line")
	if err != nil {
		return
	}
	ranges, err := godwarf.GetDebugSectionElf(elfFile, "ranges")
	if err != nil {
		return
	}
	dwarfData, err := dwarf.New(abbrev, nil, frame, info, line, nil, ranges, nil)
	if err != nil {
		return
	}
	return &ELFFile{
		binPath:   binPath,
		binFile:   binFile,
		elfFile:   elfFile,
		dwarfData: dwarfData,
	}, nil
}
