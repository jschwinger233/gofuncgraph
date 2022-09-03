package uprobe

type UprobeLocation int

const (
	AtFramePointer UprobeLocation = iota
	Custom
	AtRet
)

type Uprobe struct {
	Funcname                 string
	AbsOffset                uint64
	RelOffset                uint64
	Location                 UprobeLocation
	UserSpecified, Backtrace bool
	FetchArgs                []*FetchArg
}
