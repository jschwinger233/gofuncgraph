package uprobe

type UprobeLocation int

const (
	AtFramePointer UprobeLocation = iota
	AtRet
)

type Uprobe struct {
	Funcname                 string
	Location                 UprobeLocation
	Offset                   uint64
	UserSpecified, Backtrace bool
	FetchArgs                []*FetchArg
}
