package main

import (
	"github.com/sirupsen/logrus"
)

func deinit() {
	queue.Close()
	logrus.WithFields(logrus.Fields{
		"chain_name": chainName,
		"protocol":   protocol,
		"rule_num":   ruleNum,
		"queue_num":  queueNum,
	}).Info("the nfqueue rule deleted")

	if !debug {
		err = logFile.Close()
		if err != nil {
			logrus.WithField("error", err).Error("failed to close log file")
		}
	}

	logrus.WithField("logfile", logFile).Infoln("cnet quits")
}
