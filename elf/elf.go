package elf

import (
	"debug/dwarf"
	"debug/elf"
	"os"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
)

type ELF struct {
	bin       string
	binFile   *os.File
	elfFile   *elf.File
	dwarfData *dwarf.Data

	cache map[string]interface{}
}

func New(bin string) (_ *ELF, err error) {
	binFile, err := os.Open(bin)
	if err != nil {
		return
	}
	elfFile, err := elf.NewFile(binFile)
	if err != nil {
		return
	}
	abbrev, err := godwarf.GetDebugSectionElf(elfFile, "abbrev")
	if err != nil {
		abbrev = nil
	}
	aranges, err := godwarf.GetDebugSectionElf(elfFile, "aranges")
	if err != nil {
		aranges = nil
	}
	frame, err := godwarf.GetDebugSectionElf(elfFile, "frame")
	if err != nil {
		section := elfFile.Section(".eh_frame")
		frame = make([]byte, section.Size)
		_, err = binFile.ReadAt(frame, int64(section.Offset))
	}
	info, err := godwarf.GetDebugSectionElf(elfFile, "info")
	if err != nil {
		info = nil
	}
	line, err := godwarf.GetDebugSectionElf(elfFile, "line")
	if err != nil {
		line = nil
	}
	pubnames, err := godwarf.GetDebugSectionElf(elfFile, "pubnames")
	if err != nil {
		pubnames = nil
	}
	ranges, err := godwarf.GetDebugSectionElf(elfFile, "ranges")
	if err != nil {
		ranges = nil
	}
	str, err := godwarf.GetDebugSectionElf(elfFile, "str")
	if err != nil {
		str = nil
	}
	dwarfData, err := dwarf.New(abbrev, aranges, frame, info, line, pubnames, ranges, str)
	if err != nil {
		println("...")
		return
	}
	return &ELF{
		bin:       bin,
		binFile:   binFile,
		elfFile:   elfFile,
		dwarfData: dwarfData,
		cache:     map[string]interface{}{},
	}, nil
}
