package policy

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	// PolicyCache stores whether the Socket is defined in the Policy.
	PolicyCache *cache.Cache = cache.New(time.Hour, 2*time.Hour)
)
