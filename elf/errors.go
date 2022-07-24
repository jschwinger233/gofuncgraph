package elf

import "errors"

var (
	SymbolNotFoundError     = errors.New("symbol not found")
	DIENotFoundError        = errors.New("DIE not found")
	FramePointerNotFound    = errors.New("fp not found")
	ReturnNotFound          = errors.New("return not found")
	PcRangeTooLargeErr      = errors.New("PC range too large")
	FramePointerNotFoundErr = errors.New("framepointer not found")
	RetNotFoundErr          = errors.New("ret not found")
)
