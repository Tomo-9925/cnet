package runnotify

import (
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

type RunNotifyApi struct {
	Fs     *fsnotify.Watcher
	runCh  chan string
	killCh chan string
	errCh  chan error
}

func NewRunNotifyApi(runCh chan string, killCh chan string, errCh chan error) (*RunNotifyApi, error) {
	runNotifyApi := RunNotifyApi{Fs: nil, runCh: runCh, killCh: killCh, errCh: errCh}
	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	runNotifyApi.Fs = fs
	if err := runNotifyApi.addContainerRunMetrics(); err != nil {
		return nil, err
	}
	return &runNotifyApi, nil
}

func (runNotifyApi *RunNotifyApi) addContainerRunMetrics() error {
	if err := runNotifyApi.Fs.Add(runmetrics); err != nil {
		return err
	}
	return nil
}

func (runNotifyApi *RunNotifyApi) Start() {
	defer close(runNotifyApi.runCh)
	defer close(runNotifyApi.killCh)
	defer close(runNotifyApi.errCh)

	lastRun := ""
	lastKill := ""
	for {
		select {
		case event := <-runNotifyApi.Fs.Events:
			switch {
			case event.Op&fsnotify.Create == fsnotify.Create:
				cid := filepath.Base(event.Name)
				if lastRun == cid {
					continue
				}
				runNotifyApi.runCh <- cid
				lastRun = cid

			case event.Op&fsnotify.Remove == fsnotify.Remove:
				cid := filepath.Base(event.Name)
				if cid == lastKill {
					continue
				}

				runNotifyApi.killCh <- cid
				lastKill = cid
			}
		case err := <-runNotifyApi.Fs.Errors:
			runNotifyApi.errCh <- err
		}
	}
}
