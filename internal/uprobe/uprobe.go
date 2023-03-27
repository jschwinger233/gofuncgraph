package uprobe

type UprobeLocation int

const (
	AtEntry UprobeLocation = iota
	AtRet
)

type Uprobe struct {
	Funcname  string
	Address   uint64
	AbsOffset uint64
	RelOffset uint64
	Location  UprobeLocation
	FetchArgs []*FetchArg
}
