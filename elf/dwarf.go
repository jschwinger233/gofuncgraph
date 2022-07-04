package elf

import "debug/dwarf"

func (f *ELFFile) IterDebugInfo() <-chan *dwarf.Entry {
	ch := make(chan *dwarf.Entry)
	go func() {
		defer close(ch)
		infoReader := f.dwarfData.Reader()
		for {
			entry, err := infoReader.Next()
			if err != nil || entry == nil {
				return
			}
			ch <- entry
		}
	}()
	return ch
}
