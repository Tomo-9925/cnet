package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
	"github.com/tomo-9925/cnet/pkg/runnotify"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var queue *netfilter.NFQueue
	queue, err = netfilter.NewNFQueue(queueNum, maxPacketsInQueue, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to bind nfqueue")
	}
	packets := queue.GetPackets()

	runCh := make(chan string)
	killCh := make(chan string)
	runErrCh := make(chan error)
	runNotifyAPI := runnotify.NewAPI(runCh, killCh, runErrCh)
	go runNotifyAPI.Start()

	for {
		select {
		case s := <-sig:
			logrus.WithField("signal", s).Info("the signal received")
			logrus.Exit(0)
		case cid := <-runCh:
			//Include newly launched containers in the monitoring
			containerFields := logrus.WithFields(logrus.Fields{
				"container_id": cid,
				"containers":   containers,
			})
			container, err := container.FetchDockerContainerInspection(cid)
			if err != nil {
				containerFields.WithField("error", err).Fatal("failed to fetch docker container inspection")
			}
			containers = append(containers, container)
			containerFields.Info("the container information added")

			// Reload security policy data
			policies, err = policy.ParseSecurityPolicy(policyPath)
			if err != nil {
				containerFields.WithField("error", err).Fatal("failed to parse security policy")
			}
			logrus.WithField("policies", policies).Info("the security policy data reloaded")
		case cid := <-killCh:
			//Removing finished containers from monitoring
			container.RemoveContainerFromSlice(containers, cid)
			logrus.WithFields(logrus.Fields{
				"container_id": cid,
				"containers":   containers,
			}).Info("container information removed")
		case cid := <-runErrCh:
			logrus.WithField("container_id", cid).Info("an error occurred when starting the container")
		case p := <-packets:
			logrus.WithField("packet", p).Debug("the packet received")
			var (
				targetSocket          *proc.Socket
				communicatedContainer *container.Container
				communicatedProcess   *proc.Process
			)
			targetSocket, communicatedContainer, err = proc.CheckSocketAndCommunicatedContainer(&p.Packet, containers)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithField("error", err).Warn("the packet with unspecified structure dropped")
				continue
			}
			communicatedProcess, err = proc.IdentifyProcessOfContainer(targetSocket, communicatedContainer, &p.Packet)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				logrus.WithField("error", err).WithFields(logrus.Fields{
					"target_socket":          targetSocket,
					"communicated_container": communicatedContainer,
				}).Warn("the packet with unidentified process dropped")
				continue
			}
			communicationFields := logrus.WithFields(logrus.Fields{
				"target_socket":          targetSocket,
				"communicated_container": communicatedContainer,
				"communicated_process":   communicatedProcess,
			})
			if !policies.IsDefined(communicatedContainer, communicatedProcess, targetSocket) {
				p.SetVerdict(netfilter.NF_DROP)
				communicationFields.Info("the undefined packet dropped")
				continue
			}
			p.SetVerdict(netfilter.NF_ACCEPT)
			communicationFields.Info("the defined packet accepted")
		}
	}
}
