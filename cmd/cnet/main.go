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
		errorField.Fatal("failed to bind nfqueue")
	}
	logrus.DeferExitHandler(queue.Close)
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
			logrus.Exit(0)
		case cid := <-runCh:
			containerFields := containersField.WithField("container_id", cid)

			//Include newly launched containers in the monitoring
			container, err := container.FetchDockerContainerInspection(cid)
			if err != nil {
				containerFields.WithField("error", err).Fatal("failed to fetch docker container inspection")
			}
			containers = append(containers, container)
			containerFields.Info("container information added")

			// Reload security policy data
			policies, err = policy.ParseSecurityPolicy(policyPath)
			if err != nil {
				containerFields.WithField("error", err).Fatal("failed to parse security policy")
			}
			policiesField.Info("security policy data reloaded")
		case cid := <-killCh:
			//Removing finished containers from monitoring
			container.RemoveContainerFromSlice(containers, cid)
			logrus.WithFields(logrus.Fields{
				"container_id": cid,
				"containers": containers,
				}).Info("container information removed")
		case cid := <-runErrCh:
			logrus.WithField("container_id", cid).Info("an error occurred when starting the container")
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
				errorField.Warn("the packet with unspecified structure dropped")
				continue
			}
			if !targetSocket.IsSupportProtocol() {
				p.SetVerdict(netfilter.NF_ACCEPT)
				logrus.WithField("target_socket", targetSocket).Warn("the packet with unsupported protocol accepted")
				continue
			}
			communicatedProcess, err = proc.IdentifyProcessOfContainer(targetSocket, communicatedContainer, &p.Packet)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				errorField.WithFields(logrus.Fields{
					"target_socket": targetSocket,
					"communicated_container": communicatedContainer,
					}).Warn(err)
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
			communicationFields.Debug("the defined packet accepted")
		}
	}
}
