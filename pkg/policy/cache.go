package policy

import (
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
)

var (
	communicationCache *cache.Cache = cache.New(time.Hour, 2*time.Hour)
)

type communicationCacheKey struct {
	container *container.Container
	process   *proc.Process
	socket    *proc.Socket
}

func (c communicationCacheKey) String() string {
	return fmt.Sprintf("%p%d%s%d%s%s%d%d", c.container, c.process.ID, c.process.Path, c.socket.Protocol, c.socket.LocalIP, c.socket.RemoteIP, c.socket.LocalPort, c.socket.RemotePort)
}

// ClearCommunicationCache clear communication cache
func ClearCommunicationCache() {
	communicationCache.Flush()
}
