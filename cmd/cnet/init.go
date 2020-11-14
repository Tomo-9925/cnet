package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/network"
	"github.com/tomo-9925/cnet/pkg/policy"
)

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logrus.SetOutput(os.Stdout)

	containers, err = container.FetchDockerContainerInspections()
	if err != nil {
		errorField.Fatal("failed to initialize cnet")
	}

	policies, err = policy.ParseSecurityPolicy(policyPath)
	if err != nil {
		errorField.Fatal("failed to initialize cnet")
	}

	err = network.InsertNFQueueRule(chainName, protocol, ruleNum, queueNum)
	if err != nil {
		errorField.Fatal("failed to initialize cnet")
	}

	// Configure logrus
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		// Writing to the file in the production environment only
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
		logFile, err = os.OpenFile(logFilePath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			0666)
		if err != nil {
			errorField.Fatal("failed to initialize cnet")
		}
		logrus.SetOutput(logFile)
	}
	logrus.DeferExitHandler(deinit)

	logrus.WithFields(logrus.Fields{
		"logfile":    logFile,
		"containers": containers,
		"policies":   policies,
	}).Info("cnet initialized")
}
