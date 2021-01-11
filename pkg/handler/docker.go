package handler

import (
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/policy"
)

func AddDockerContainerInspection(cid string, containers *container.Containers, policies *policy.Policies, waitGroup *sync.WaitGroup, semaphore chan int) {
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
		containerFields.WithField("error", err).Error("failed to parse security policy")
	}
	logrus.WithField("policies", policies).Info("the security policy data reloaded")

	clearCache()
}

func RemoveDockerContainerInspection(cid string, containers *container.Containers, policies *policy.Policies, waitGroup *sync.WaitGroup, semaphore chan int) {
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

	clearCache()
}
