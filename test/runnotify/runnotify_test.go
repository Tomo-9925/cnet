package runnotify_test

import (
	"testing"
	"os"
	"github.com/tomo-9925/cnet/pkg/runnotify"
	"github.com/tomo-9925/cnet/pkg/container"
)

func TestMain(m *testing.M) {
		err := container.ConnectCli()
		if err != nil {
			os.Exit(1)
		}
    m.Run()
}

func TestRunnotify(t *testing.T) {
	runCh := make(chan string)
	killCh := make(chan string)
	runErrCh := make(chan error)
	runNotifyApi:= runnotify.NewRunNotifyApi(runCh,killCh,runErrCh)
	if runNotifyApi.Messages == nil{
		t.Fatal("failed to innitialize runNotifyApi(Messages is nil)")
	}else if runNotifyApi.Err == nil{
		t.Fatal("failed to innitialize runNotifyApi(Err is nil)")
	}
}
