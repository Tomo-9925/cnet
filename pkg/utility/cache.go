package utility

import (
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
)

// ClearCache clears cache of policy and proc package.
func ClearCache() {
	logrus.Infoln("clear cache")
	proc.SocketCache.Flush()
	policy.PolicyCache.Flush()
}
