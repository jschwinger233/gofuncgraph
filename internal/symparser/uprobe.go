package symparser

type UprobeLocation int

const (
	AtEntry UprobeLocation = iota
	AtFramePointer
	AtRet
)

type Uprobe struct {
	Funcname                 string
	Location                 UprobeLocation
	Offset                   uint64
	UserSpecified, Backtrace bool
}
