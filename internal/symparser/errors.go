package symparser

import "errors"

var (
	DIENotFoundError     = errors.New("DIE not found")
	FramePointerNotFound = errors.New("fp not found")
	ReturnNotFound       = errors.New("return not found")
)
