package main

import (
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/network"
)

func deinit() {
	err = network.DeleteNFQueueRule(chainName, protocol, queueNum)
	if err != nil {
		logrus.WithField("error", err).Error("failed to delete the nfqueue rule")
	}

	if !debug {
		err = logFile.Close()
		if err != nil {
			logrus.WithField("error", err).Error("failed to close log file")
		}
	}

	logrus.Infoln("cnet quits")
}
