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
	if ExistNFQueueRule(chainName, protocol, queueNum) {
		logrus.WithFields(argFields).Debug("NFQueue is already added")
		return nil
	}
	out, err := exec.Command(
		"iptables",
		"-A", chainName,
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).Output()
	if err != nil {
		return errors.New(*(*string)(unsafe.Pointer(&out)))
	}
	logrus.WithFields(argFields).Debug("NFQueue is added")
	return nil
}

// DeleteNFQueueRule delete NFQueue rule in the specified chain.
func DeleteNFQueueRule(chainName string, protocol string, queueNum uint16) error {
	argFields := logrus.Fields{
		"chainName": chainName,
		"protocol":  protocol,
		"queueNum":  queueNum,
	}
	if !ExistNFQueueRule(chainName, protocol, queueNum) {
		logrus.WithFields(argFields).Debug("NFQueue is already deleted")
		return nil
	}
	out, err := exec.Command(
		"iptables",
		"-D", chainName,
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).Output()
	if err != nil {
		return errors.New(*(*string)(unsafe.Pointer(&out)))
	}
	logrus.WithFields(argFields).Debug("NFQueue is deleted")
	return nil
}

// ExistNFQueueRule reports whether NFQueue rule is existed.
func ExistNFQueueRule(chainName string, protocol string, queueNum uint16) bool {
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
