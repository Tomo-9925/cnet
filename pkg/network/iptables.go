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

// InsertNFQueueRule insert NFQueue rule in the specified chain and rule number.
func InsertNFQueueRule(chainName, protocol string, ruleNum, queueNum uint16) error {
	argFields := logrus.Fields{
		"chainName": chainName,
		"protocol":  protocol,
		"ruleNum": ruleNum,
		"queueNum":  queueNum,
	}
	if ExistsNFQueueRule(chainName, protocol, queueNum) {
		logrus.WithFields(argFields).Debug("NFQueue is exists")
		return nil
	}
	out, err := exec.Command(
		"iptables",
		"-I", chainName, strconv.Itoa(int(ruleNum)),
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).CombinedOutput()
	if err != nil {
		return errors.New(*(*string)(unsafe.Pointer(&out)))
	}
	logrus.WithFields(argFields).Debug("NFQueue is inserted")
	return nil
}

// DeleteNFQueueRule delete NFQueue rule in the specified chain.
func DeleteNFQueueRule(chainName, protocol string, queueNum uint16) error {
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
func ExistsNFQueueRule(chainName, protocol string, queueNum uint16) bool {
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
