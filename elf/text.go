package elf

func (e *ELF) Text() (bytes []byte, err error) {
	if _, ok := e.cache["textBytes"]; !ok {
		if e.cache["textBytes"], err = e.SectionBytes(".text"); err != nil {
			return
		}
	}
	return e.cache["textBytes"].([]byte), nil
}
