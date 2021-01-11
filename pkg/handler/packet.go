package handler

import (
	"sync"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/docker"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
)

func PacketHandler(p *netfilter.NFPacket, containers *docker.Containers, policies *policy.Policies, waitGroup *sync.WaitGroup, semaphore chan int) {
	waitGroup.Add(1)
	semaphore <- 1
	defer func(){
		<- semaphore
		waitGroup.Done()
	}()

	logrus.WithField("packet", *p).Debug("the packet received")
	var (
		targetSocket          *proc.Socket
		communicatedContainer *container.Container
		communicatedProcess   *proc.Process
		err                   error
	)
	targetSocket, communicatedContainer, err = proc.CheckSocketAndCommunicatedDockerContainer(&p.Packet, containers)
	if err != nil {
		p.SetVerdict(netfilter.NF_DROP)
		logrus.WithField("error", err).Warn("the packet with unspecified structure dropped")
		return
	}
	communicatedProcess, err = proc.IdentifyProcessOfContainer(targetSocket, communicatedContainer, &p.Packet)
	if err != nil {
		p.SetVerdict(netfilter.NF_DROP)
		logrus.WithField("error", err).WithFields(logrus.Fields{
			"target_socket":          targetSocket,
			"communicated_container": communicatedContainer,
		}).Warn("the packet with unidentified process dropped")
		return
	}
	communicationFields := logrus.WithFields(logrus.Fields{
		"target_socket":          targetSocket,
		"communicated_container": communicatedContainer,
		"communicated_process":   communicatedProcess,
	})
	if policies.IsDefined(communicatedContainer, communicatedProcess, targetSocket) {
		p.SetVerdict(netfilter.NF_ACCEPT)
		communicationFields.Info("the defined packet accepted")
		return
	}
	p.SetVerdict(netfilter.NF_DROP)
	communicationFields.Info("the undefined packet dropped")
}
