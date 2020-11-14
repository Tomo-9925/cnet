package main

import (
	"os"

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
	logFile         *os.File
	containers      []*container.Container
	policies        policy.Policies
)
