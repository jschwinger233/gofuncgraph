package elf

import "github.com/pkg/errors"

func (e *ELF) Text() (bytes []byte, err error) {
	if _, ok := e.cache["textBytes"]; !ok {
		if e.cache["textBytes"], err = e.SectionBytes(".text"); err != nil {
			return
		}
	}
	return e.cache["textBytes"].([]byte), nil
}

func (e *ELF) FuncRawInstructions(name string) (textBytes []byte, addr, offset uint64, err error) {
	lowpc, highpc, err := e.FuncPcRangeInDwarf(name)
	if err != nil {
		if lowpc, highpc, err = e.FuncPcRangeInSymtab(name); err != nil {
			return
		}
	}

	section := e.Section(".text")
	if textBytes, err = e.Text(); err != nil {
		return
	}

	if highpc > uint64(len(textBytes))+section.Addr || lowpc < section.Addr {
		err = errors.Wrap(PcRangeTooLargeErr, name)
		return
	}
	return textBytes[lowpc-section.Addr : highpc-section.Addr], lowpc, lowpc - section.Addr + section.Offset, nil
}
