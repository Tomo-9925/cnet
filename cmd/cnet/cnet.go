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
	logFilePath string = "./cnet.log"
	policyPath  string = "./policy.yml"

	// iptables settings
	chainName string = "DOCKER-USER"
	ruleNum   uint16 = 1
	protocol  string = "all"
	queueNum  uint16 = 2

	// NFQueue settings
	maxPacketsInQueue uint32 = 1000
)

var (
	err        error
	logFile    *os.File
	containers *container.Containers
	policies   policy.Policies
	logLevel   logrus.Level
)
