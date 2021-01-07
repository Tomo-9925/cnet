package policy

import (
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/tomo-9925/cnet/pkg/proc"
)

var (
	CommunicationCache *cache.Cache = cache.New(time.Hour, 2*time.Hour)
)

type communicationCacheKey struct {
	process *proc.Process
	socket  *proc.Socket
}

func (c communicationCacheKey) String() string {
	return fmt.Sprintf("%s%d%s", c.socket, c.process.ID, c.process.Path)
}
