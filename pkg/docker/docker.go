package docker

import (
	"io/ioutil"
	"strconv"
	"unsafe"

	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)


var (
	// PID is docker daemon pid
	PID int

	cli  *client.Client
)

func init() {
	logrus.Debug("trying to initialize docker engine api client")
	var err error
	cli, err = client.NewEnvClient()
	cliField := logrus.WithField("client", *cli)
	if err != nil {
		cliField.WithField("error", err).Fatal("faild to initialize docker engine api client")
	}
	cliField.Debug("docker engine api client initialized")

	logrus.Debug("trying to retrieve pid of docker daemon")
	var file []byte
	file, err = ioutil.ReadFile("/var/run/docker.pid")
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to retrieve dockerd process id")
	}
	PID, err = strconv.Atoi(*(*string)(unsafe.Pointer(&file)))
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to retrieve dockerd process id")
	}
}
