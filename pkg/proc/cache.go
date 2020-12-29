package proc

import (
	"github.com/tomo-9925/cnet/pkg/container"
)

var (
	inodeCache inodeCacheMap = make(inodeCacheMap)
)

type inodeCacheMapKey struct {
	container *container.Container
	socket string
	inode uint64
}

type inodeCacheMapValue struct {
	fd uint64
	process *Process
}

type inodeCacheMap map[inodeCacheMapKey]inodeCacheMapValue

// ClearInodeCache clear inodeCache map of proc package
func ClearInodeCache() {
	inodeCache = make(inodeCacheMap)
}
