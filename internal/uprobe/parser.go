package uprobe

import (
	"github.com/jschwinger233/ufuncgraph/elf"
)

type ParseOptions struct {
	Wildcards   []string
	ExWildcards []string
	Fetch       map[string]map[string]string
	SearchDepth int
	Backtrace   bool
	Lang        string
}

func Parse(elf *elf.ELF, opts *ParseOptions) (uprobes []Uprobe, err error) {
	fetchArgs, err := parseFetchArgs(opts.Fetch)
	if err != nil {
		return
	}

	funcTrees, err := parseFuncTrees(elf, opts.Wildcards, opts.ExWildcards, opts.SearchDepth)
	if err != nil {
		return
	}

	visited := map[string]interface{}{}
	for _, tree := range funcTrees {
		tree.Print(opts.Lang)
		tree.Traverse(func(layer int, parent, self *FuncTree) bool {
			if _, ok := visited[self.Name]; ok {
				return false
			}
			visited[self.Name] = nil
			userSpecified := layer == 0
			switch opts.Lang {
			case "go":
				if self.Err != nil {
					return true
				}
				uprobes = append(uprobes, Uprobe{
					Funcname:      self.Name,
					Location:      AtFramePointer,
					Offset:        self.FpOffset,
					UserSpecified: userSpecified,
					Backtrace:     userSpecified && opts.Backtrace,
					FetchArgs:     fetchArgs[self.Name],
				})
				for _, off := range self.RetOffsets {
					uprobes = append(uprobes, Uprobe{
						Funcname: self.Name,
						Location: AtRet,
						Offset:   off,
					})
				}

			case "c":
				uprobes = append(uprobes, Uprobe{
					Funcname:      self.Name,
					Location:      AtEntry,
					Offset:        self.EntOffset,
					UserSpecified: userSpecified,
					Backtrace:     userSpecified && opts.Backtrace,
					FetchArgs:     fetchArgs[self.Name],
				})
			}
			return true
		})
	}
	return
}
