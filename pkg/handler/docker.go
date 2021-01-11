package handler

import (
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/docker"
	"github.com/tomo-9925/cnet/pkg/policy"
)

func AddDockerContainerInspection(cid string, containers *docker.Containers, policies *policy.Policies, waitGroup *sync.WaitGroup, semaphore chan int) {
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
	err := containers.AddContainer(cid)
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

func RemoveDockerContainerInspection(cid string, containers *docker.Containers, policies *policy.Policies, waitGroup *sync.WaitGroup, semaphore chan int) {
	waitGroup.Add(1)
	semaphore <- 1
	defer func(){
		<- semaphore
		waitGroup.Done()
	}()

	containers.RemoveContainer(cid)
	logrus.WithFields(logrus.Fields{
		"container_id": cid,
		"containers":   containers,
	}).Info("the container inspection removed")

	clearCache()
}
