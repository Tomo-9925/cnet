package main

import (
	"os"

	"github.com/sirupsen/logrus"

	"github.com/tomo-9925/cnet/pkg/docker"
	"github.com/tomo-9925/cnet/pkg/policy"
)

const (
	debug bool = false

	// File path
	logFilePath string = "./cnet.log"
	policyPath  string = "./policy.yml"

	// iptables settings
	chainName string = "DOCKER-USER"
	ruleNum   uint16 = 1
	protocol  string = "all"
	queueNum  uint16 = 2

	// NFQueue settings
	maxPacketsInQueue uint32 = 10000
)

var (
	err        error
	logFile    *os.File
	containers *docker.Containers
	policies   *policy.Policies
	logLevel   logrus.Level
)
