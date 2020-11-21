package main

import (
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/network"
	"github.com/tomo-9925/cnet/pkg/policy"
)

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logrus.SetOutput(os.Stdout)

	var logLevelFlag *string
	var defaultLogLevel string

	if debug {
		defaultLogLevel = "DEBUG"
	} else {
		defaultLogLevel = "INFO"
	}

	logLevelFlag = flag.String("logLevel", defaultLogLevel, "specify logLevel")
	flag.Parse()
	switch *logLevelFlag {
	case "FATAL":
		logLevel = logrus.FatalLevel
	case "ERROR":
		logLevel = logrus.ErrorLevel
	case "WARN":
		logLevel = logrus.WarnLevel
	case "INFO":
		logLevel = logrus.InfoLevel
	case "DEBUG":
		logLevel = logrus.DebugLevel
	case "TRACE":
		logLevel = logrus.TraceLevel
	default:
		logrus.WithField("logLevelFlag", *logLevelFlag).Fatal("the specified logLevel does not exist")
	}

	// Configure logrus
	logrus.SetLevel(logLevel)

	containers, err = container.FetchDockerContainerInspections()
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to initialize cnet")
	}
	logrus.WithField("containers", containers).Info("container information fetched")

	policies, err = policy.ParseSecurityPolicy(policyPath)
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to initialize cnet")
	}
	logrus.WithField("policies", policies).Info("the security policy loaded")

	err = network.InsertNFQueueRule(chainName, protocol, ruleNum, queueNum)
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to initialize cnet")
	}
	logrus.WithFields(logrus.Fields{
		"chain_name": chainName,
		"protocol":   protocol,
		"rule_num":   ruleNum,
		"queue_num":  queueNum,
	}).Info("the nfqueue rule added")

	if !debug {
		// Writing to a file in production environment only
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
		logFile, err = os.OpenFile(logFilePath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			0666)
		if err != nil {
			logrus.WithField("error", err).Fatal("failed to initialize cnet")
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
