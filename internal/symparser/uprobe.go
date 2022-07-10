package symparser

type UprobeLocation int

const (
	AtEntry UprobeLocation = iota
	AtExit
)

type Uprobe struct {
	Funcname string
	Location UprobeLocation
	Offset   uint64
	Root     bool
}
