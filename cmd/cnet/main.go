package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/tomo-9925/cnet/pkg/runnotify"

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
	ruleNum   uint16 = 1
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
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logrus.SetOutput(os.Stdout)

	containers, err = container.FetchDockerContainerInspections()
	if err != nil {
		logrus.Fatalln(err)
	}

	policies, err = policy.ParseSecurityPolicy(policyPath)
	if err != nil {
		logrus.Fatalln(err)
	}

	err = network.InsertNFQueueRule(chainName, protocol, ruleNum, queueNum)
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
	}).Info("cnet initialized")
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

	runCh := make(chan string)
	killCh := make(chan string)
	runErrCh := make(chan error)

	runNotifyAPI := runnotify.NewAPI(runCh, killCh, runErrCh)
	go runNotifyAPI.Start()

	for {
		select {
		case s := <-sig:
			logrus.WithField("signal", s).Info("signal received")
			return
		case cid := <-runCh:
			logrus.WithField("RUN cid:", cid).Info("Container start")

			//Include newly launched containers in the monitoring
			container, err := container.FetchDockerContainerInspection(cid)
			if err != nil {
				logrus.Fatalln(err)
			}
			containers = append(containers, container)

			// Reload security policy data
			policies, err = policy.ParseSecurityPolicy(policyPath)
			if err != nil {
				logrus.Fatalln(err)
			}
		case cid := <-killCh:
			logrus.WithField("RUN cid:", cid).Info("Container stop")
			//Removing finished containers from monitoring
			container.RemoveContainerFromSlice(containers, cid)
		case cid := <-runErrCh:
			logrus.WithField("RUN cid:", cid).Info("An error occurred when starting the container")
		case p := <-packets:
			logrus.WithField("packet", p).Debug("packet received")
			var (
				targetSocket          *proc.Socket
				communicatedContainer *container.Container
				communicatedProcess   *proc.Process
			)
			targetSocket, communicatedContainer, err = proc.CheckSocketAndCommunicatedContainer(&p.Packet, containers)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithField("packet", p).Warn(err)
				continue
			}
			// OPTIMIZE: Maybe we should memoization.
			if !targetSocket.IsSupportProtocol() {
				p.SetVerdict(netfilter.NF_ACCEPT)
				logrus.WithField("socket", targetSocket).Info("packet accepted")
				continue
			}
			communicatedProcess, err = proc.IdentifyProcessOfContainer(targetSocket, communicatedContainer, &p.Packet)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithField("socket", targetSocket).Warn(err)
				continue
			}
			communicationField := logrus.Fields{
				"socket":    targetSocket,
				"container": communicatedContainer,
				"process":   communicatedProcess,
			}
			if !policies.IsDefined(communicatedContainer, communicatedProcess, targetSocket) {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithFields(communicationField).Warn("packet dropped")
				continue
			}
			p.SetVerdict(netfilter.NF_ACCEPT)
			logrus.WithFields(communicationField).Debug("packet accepted")
		}
	}
}
