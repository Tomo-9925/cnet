package proc

import "github.com/tomo-9925/cnet/pkg/container"

var (
	inodeCache inodeCacheMap = make(inodeCacheMap)
)

type inodeCacheMapKey struct {
	container *container.Container
	inode uint64
}

type inodeCacheMapValue struct {
	fd uint64
	process *Process
}

type inodeCacheMap map[inodeCacheMapKey]*inodeCacheMapValue

func (m inodeCacheMap) ClearInodeCache() {
	inodeCache = make(inodeCacheMap)
}
