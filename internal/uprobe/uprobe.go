package uprobe

type UprobeLocation int

const (
	AtEntry UprobeLocation = iota
	AtRet
)

type Uprobe struct {
	Funcname  string
	AbsOffset uint64
	RelOffset uint64
	Location  UprobeLocation
	FetchArgs []*FetchArg
}
