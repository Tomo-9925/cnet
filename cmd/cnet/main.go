package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/network"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
)

const (
	debug bool = true

	// File path
	logFilePath string = "./network.log"
	policyPath  string = "./policy.yml"

	// iptables settings
	chainName string = "DOCKER-USER"
	insertPos   uint16 = 1
	protocol  string = "all"
	queueNum  uint16 = 2

	// NFQueue settings
	maxPacketsInQueue uint32 = 100
)

var (
	err        error
	logFile    *os.File
	containers []*container.Container
	policies   policy.Policies
)

func init() {
	// Configure the basic setup of logrus
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logrus.SetOutput(os.Stdout)

	// Get Docker container informations
	containers, err = container.GetDockerContainerInformations()
	if err != nil {
		logrus.Fatalln(err)
	}

	// Get security policy data
	policies, err = policy.ParseSecurityPolicy(policyPath, containers)
	if err != nil {
		logrus.Fatalln(err)
	}

	// Configure iptables
	err = network.InsertNFQueueRule(chainName, protocol, insertPos, queueNum)
	if err != nil {
		logrus.Fatalln(err)
	}

	// Configure logrus
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
		logFile, err = os.OpenFile(logFilePath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			0666)
		if err != nil {
			logrus.Fatalln(err)
		}
		logrus.SetOutput(logFile)
	}
	logrus.WithFields(logrus.Fields{
		"logfile":    logFile,
		"containers": containers,
		"policies":   policies,
	}).Debug("Cnet initialized")
}

func deinit() {
	if !debug {
		err = network.DeleteNFQueueRule(chainName, protocol, queueNum)
		if err != nil {
			logrus.Errorln(err)
		}
		err = logFile.Close()
		if err != nil {
			logrus.Errorln(err)
		}
	}
}

func main() {
	defer deinit()

	// Hook signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	// Hook NFQueue
	var queue *netfilter.NFQueue
	queue, err = netfilter.NewNFQueue(queueNum, maxPacketsInQueue, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		deinit()
		logrus.Fatalln(err)
	}
	defer queue.Close()
	packets := queue.GetPackets()

	// TODO: Container start-up detection and file change detection.
	// 全体報告会の資料添削のときに，以前のシステム構成のことを思い出しました…

	for {
		select {
		case s := <-sig:
			logrus.WithField("signal", s).Info("signal received")
			return
		case p := <-packets:
			logrus.WithField("packet", p).Debug("packet received")
			var (
				pSocket    *proc.Socket
				pContainer *container.Container
				pProcess   *proc.Process
			)
			pSocket, pContainer, err = proc.CheckSocketAndCommunicatedContainer(&p.Packet, containers)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithField("packet", p).Warn(err)
				continue
			}
			// OPTIMIZE: Maybe we should memoization.
			if !pSocket.IsSupportProtocol() {
				p.SetVerdict(netfilter.NF_ACCEPT)
				logrus.WithField("socket", pSocket).Info("packet accepted")
				continue
			}
			pProcess, err = proc.IdentifyProcessOfContainer(pSocket, pContainer, &p.Packet)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithField("socket", pSocket).Warn(err)
				continue
			}
			communicationField := logrus.Fields{
				"socket":    pSocket,
				"container": pContainer,
				"process":   pProcess,
			}
			if !policies.IsDefined(pContainer, pProcess, pSocket) {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithFields(communicationField).Warn("packet dropped")
				continue
			}
			p.SetVerdict(netfilter.NF_ACCEPT)
			logrus.WithFields(communicationField).Debug("packet accepted")
		}
	}
}
