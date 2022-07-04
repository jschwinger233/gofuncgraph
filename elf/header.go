package elf

import "debug/elf"

func (f *ELFFile) Section(s string) *elf.Section {
	return f.elfFile.Section(s)
}

func (f *ELFFile) SectionBytes(s string) (bytes []byte, err error) {
	section := f.elfFile.Section(s)
	bytes = make([]byte, section.Size)
	_, err = f.binFile.ReadAt(bytes, int64(section.Offset))
	return
}
