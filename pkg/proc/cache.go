package proc

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	// SocketCache stores the Process identified by the Socket
	SocketCache *cache.Cache = cache.New(time.Hour, 2*time.Hour)
)
