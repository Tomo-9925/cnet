package handler

import (
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
)

func clearCache() {
	logrus.Infoln("clear cache")
	proc.SocketCache.Flush()
	policy.PolicyCache.Flush()
}
