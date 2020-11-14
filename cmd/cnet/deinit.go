package main

import (
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/network"
)

func deinit() {
	err = network.DeleteNFQueueRule(chainName, protocol, queueNum)
	if err != nil {
		errorField.Error("failed to deinit function")
	}

	if !debug {
		err = logFile.Close()
		if err != nil {
			errorField.Error("failed to deinit function")
		}
	}

	logrus.Infoln("cnet quits")
}
