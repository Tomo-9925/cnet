package main

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
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

	waitGroup := &sync.WaitGroup{}
	semaphore := make(chan int, runtime.NumCPU())

	for {
		select {
		case s := <-sig:
			waitGroup.Wait()
			logrus.WithField("signal", s).Info("the signal received")
			logrus.Exit(0)
		case cid := <-runCh:
			waitGroup.Wait()
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

			logrus.Infoln("clear cache")
			proc.SocketCache.Flush()
			policy.PolicyCache.Flush()
		case cid := <-killCh:
			waitGroup.Wait()
			//Removing finished containers from monitoring
			container.RemoveContainerFromSlice(containers, cid)
			logrus.WithFields(logrus.Fields{
				"container_id": cid,
				"containers":   containers,
			}).Info("container information removed")
			logrus.Infoln("clear cache")
			proc.SocketCache.Flush()
			policy.PolicyCache.Flush()
		case cid := <-runErrCh:
			waitGroup.Wait()
			logrus.WithField("container_id", cid).Info("an error occurred when starting the container")
		case p := <-packets:
			go packetHandler(&p, waitGroup, semaphore)
		}
	}
}
