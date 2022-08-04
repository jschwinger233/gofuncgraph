package uprobe

type UprobeLocation int

const (
	At0 UprobeLocation = iota
	AtFramePointer
	AtRet
)

type Uprobe struct {
	Funcname                 string
	Location                 UprobeLocation
	Offset                   uint64
	UserSpecified, Backtrace bool
	FetchArgs                []*FetchArg
}
