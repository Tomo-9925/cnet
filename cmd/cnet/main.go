package main

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/sirupsen/logrus"
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
			go addContainer(cid, waitGroup, semaphore)
		case cid := <-killCh:
			go removeContainer(cid, waitGroup, semaphore)
		case cid := <-runErrCh:
			logrus.WithField("container_id", cid).Info("an error occurred when starting the container")
		case p := <-packets:
			go packetHandler(&p, waitGroup, semaphore)
		}
	}
}
