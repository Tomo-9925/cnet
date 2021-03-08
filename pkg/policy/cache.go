package policy

import (
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	// PolicyCache stores whether the Socket is defined in the Policy.
	PolicyCache *cache.Cache = cache.New(time.Hour, 2*time.Hour)
)

func GenerateHash(container *container.Container, proc *proc.Process, socket *proc.Socket) string {
	return container.Hash() + proc.Hash() + socket.Hash()
}


