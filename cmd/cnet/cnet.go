package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/policy"
)

const (
	debug bool = true

	// File path
	logFilePath string = "./network.log"
	policyPath  string = "./policy.yml"

	// iptables settings
	chainName string = "DOCKER-USER"
	ruleNum   uint16 = 1
	protocol  string = "all"
	queueNum  uint16 = 2

	// NFQueue settings
	maxPacketsInQueue uint32 = 100
)

var (
	err             error
	errorField      *logrus.Entry = logrus.WithField("error", err)
	logFile         *os.File
	containers      []*container.Container
	containersField *logrus.Entry = logrus.WithField("containers", containers)
	policies        policy.Policies
	policiesField   *logrus.Entry = logrus.WithField("policies", policies)
)
