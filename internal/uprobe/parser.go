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
		tree.Print(0)
		tree.Traverse(func(layer int, parent, self *FuncTree) bool {
			if _, ok := visited[self.Name]; ok {
				return false
			}
			visited[self.Name] = nil
			if self.Err != nil {
				return true
			}

			userSpecified := layer == 0
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
			return true
		})
	}
	return
}
