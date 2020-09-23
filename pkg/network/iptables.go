package network

import (
	"errors"
	"os/exec"
	"strconv"
	"unsafe"

	"github.com/sirupsen/logrus"
)

const (
	jumpTarget string = "NFQUEUE"
)

// AppendNFQueueRule append NFQueue rule in the specified chain.
func AppendNFQueueRule(chainName string, protocol string, queueNum uint16) error {
	argFields := logrus.Fields{
		"chainName": chainName,
		"protocol":  protocol,
		"queueNum":  queueNum,
	}
	if ExistsNFQueueRule(chainName, protocol, queueNum) {
		logrus.WithFields(argFields).Debug("NFQueue is exists")
		return nil
	}
	out, err := exec.Command(
		"iptables",
		"-A", chainName,
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).CombinedOutput()
	if err != nil {
		return errors.New(*(*string)(unsafe.Pointer(&out)))
	}
	logrus.WithFields(argFields).Debug("NFQueue is exists")
	return nil
}

// DeleteNFQueueRule delete NFQueue rule in the specified chain.
func DeleteNFQueueRule(chainName string, protocol string, queueNum uint16) error {
	argFields := logrus.Fields{
		"chainName": chainName,
		"protocol":  protocol,
		"queueNum":  queueNum,
	}
	if !ExistsNFQueueRule(chainName, protocol, queueNum) {
		logrus.WithFields(argFields).Debug("NFQueue is not exists")
		return nil
	}
	out, err := exec.Command(
		"iptables",
		"-D", chainName,
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).CombinedOutput()
	if err != nil {
		return errors.New(*(*string)(unsafe.Pointer(&out)))
	}
	logrus.WithFields(argFields).Debug("NFQueue is deleted")
	return nil
}

// ExistsNFQueueRule reports whether NFQueue rule is existed.
func ExistsNFQueueRule(chainName string, protocol string, queueNum uint16) bool {
	err := exec.Command(
		"iptables",
		"-C", chainName,
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).Run()
	if err != nil {
		return false
	}
	return true
}