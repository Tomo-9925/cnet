package main

import (
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
)

func addContainerInspection(cid string, waitGroup *sync.WaitGroup, semaphore chan int) {
	waitGroup.Add(1)
	semaphore <- 1
	defer func(){
		<- semaphore
		waitGroup.Done()
	}()

	containerFields := logrus.WithFields(logrus.Fields{
		"container_id": cid,
		"containers":   containers,
	})
	err := container.AddDockerContainerToList(containers, cid)
	if err != nil {
		containerFields.WithField("error", err).Error("failed to add the container inspection")
	}
	containerFields.WithField("containers", containers).Info("the container inspection added")

	err = policies.Reload()
	if err != nil {
		containerFields.WithField("error", err).Fatal("failed to parse security policy")
	}
	logrus.WithField("policies", policies).Info("the security policy data reloaded")

	logrus.Infoln("clear cache")
	proc.SocketCache.Flush()
	policy.PolicyCache.Flush()
}

func removeContainerInspection(cid string, waitGroup *sync.WaitGroup, semaphore chan int) {
	waitGroup.Add(1)
	semaphore <- 1
	defer func(){
		<- semaphore
		waitGroup.Done()
	}()

	container.RemoveDockerContainerFromList(containers, cid)
	logrus.WithFields(logrus.Fields{
		"container_id": cid,
		"containers":   containers,
	}).Info("the container inspection removed")
	logrus.Infoln("clear cache")
	proc.SocketCache.Flush()
	policy.PolicyCache.Flush()
}
