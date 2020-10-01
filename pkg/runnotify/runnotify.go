package runnotify

import (
	"path/filepath"

	"github.com/tomo-9925/cnet/pkg/container"

	"github.com/docker/docker/api/types/events"
)

type RunNotifyApi struct {
	Messages <-chan events.Message
	Err      <-chan error
	runCh    chan string
	killCh   chan string
	errCh    chan error
}

// NewRunNotifyApi return the RunNotifyApi
func NewRunNotifyApi(runCh chan string, killCh chan string, errCh chan error) (*RunNotifyApi, error) {
	runNotifyApi := RunNotifyApi{Messages: nil, runCh: runCh, killCh: killCh, errCh: errCh}
	runNotifyApi.Messages, runNotifyApi.Err = container.NewWatcher()

	return &runNotifyApi, nil
}

// Start starts monitoring
func (runNotifyApi *RunNotifyApi) Start() {
	defer close(runNotifyApi.runCh)
	defer close(runNotifyApi.killCh)
	defer close(runNotifyApi.errCh)

	lastRun := ""
	lastKill := ""
	for {
		select {
		case msg := <-runNotifyApi.Messages:
			switch {
			case msg.Type == "create":
				cid := filepath.Base(msg.ID)
				if lastRun == cid {
					continue
				}
				runNotifyApi.runCh <- cid
				lastRun = cid

			case msg.Type == "destory":
				cid := filepath.Base(msg.ID)
				if cid == lastKill {
					continue
				}

				runNotifyApi.killCh <- cid
				lastKill = cid
			}
		case err := <-runNotifyApi.Err:
			runNotifyApi.errCh <- err
		}
	}
}
