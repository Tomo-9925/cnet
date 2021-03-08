package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/network"
)

func deinit() {
	err = network.DeleteNFQueueRule(chainName, protocol, queueNum)
	if err != nil {
		logrus.WithField("error", err).Error("failed to delete the nfqueue rule")
	}
	logrus.WithFields(logrus.Fields{
		"chain_name": chainName,
		"protocol": protocol,
		"rule_num": ruleNum,
		"queue_num": queueNum,
	}).Info("the nfqueue rule deleted")

	logrus.WithField("logfile", logFile).Infoln("cnet quits")

	if !debug {
		err = logFile.Close()
		if err != nil {
			logrus.SetOutput(os.Stderr)
			logrus.WithField("error", err).Error("failed to close log file")
		}
	}
}
