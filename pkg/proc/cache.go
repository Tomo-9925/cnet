package proc

import (
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/tomo-9925/cnet/pkg/container"
)

var (
	inodeCache *cache.Cache = cache.New(time.Hour, 2*time.Hour)
)

type inodeCacheKey struct {
	container *container.Container
	socket *Socket
	inode uint64
}

func (i inodeCacheKey) String() string {
	return fmt.Sprintf("%p%d%s%s%d%d%d", i.container, i.socket.Protocol, i.socket.LocalIP, i.socket.RemoteIP, i.socket.LocalPort, i.socket.RemotePort, i.inode)
}

// ClearInodeCache clear inode cache
func ClearInodeCache() {
	inodeCache.Flush()
}
