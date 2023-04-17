package elf

import "debug/elf"

func (e *ELF) FindGOffset() (offset int64, err error) {
	_, symnames, err := e.Symbols()
	if err != nil {
		return
	}
	tlsg, tlsgExists := symnames["runtime.tlsg"]
	tls := e.Prog(elf.PT_TLS)
	if tlsgExists && tls != nil {
		memsz := tls.Memsz + (-tls.Vaddr-tls.Memsz)&(tls.Align-1)
		return int64(^(memsz) + 1 + tlsg.Value), nil
	}
	return -8, nil
}
