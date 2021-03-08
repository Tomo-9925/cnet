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
func InsertNFQueueRule(chainName, protocol string, ruleNum, queueNum uint16) (err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"chain_name": chainName,
		"protocol":  protocol,
		"rule_num": ruleNum,
		"queue_num":  queueNum,
	})
	argFields.Debug("trying to insert nfqueue rule")
	if ExistsNFQueueRule(chainName, protocol, queueNum) {
		argFields.Debug("the nfqueue rule existed, so iptables setting not changed")
		return
	}
	var out []byte
	out, err = exec.Command(
		"iptables",
		"-I", chainName, strconv.Itoa(int(ruleNum)),
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).CombinedOutput()
	if err != nil {
		argFields.WithField("error", err).Debug("failed to insert the nfqueue rule")
		return errors.New(*(*string)(unsafe.Pointer(&out)))
	}
	argFields.Debug("the nfqueue rule inserted")
	return
}

// DeleteNFQueueRule delete NFQueue rule in the specified chain.
func DeleteNFQueueRule(chainName, protocol string, queueNum uint16) (err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"chainName": chainName,
		"protocol":  protocol,
		"queueNum":  queueNum,
	})
	if !ExistsNFQueueRule(chainName, protocol, queueNum) {
		argFields.Debug("the nfqueue rule existed, so iptables setting not changed")
		return
	}
	var out []byte
	out, err = exec.Command(
		"iptables",
		"-D", chainName,
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).CombinedOutput()
	if err != nil {
		argFields.WithField("error", err).Debug("failed to delete the nfqueue rule")
		return errors.New(*(*string)(unsafe.Pointer(&out)))
	}
	argFields.Debug("the nfqueue rule deleted")
	return
}

// ExistsNFQueueRule reports whether NFQueue rule is existed.
func ExistsNFQueueRule(chainName, protocol string, queueNum uint16) (exist bool) {
	err := exec.Command(
		"iptables",
		"-C", chainName,
		"-p", protocol,
		"-j", jumpTarget,
		"--queue-num", strconv.Itoa(int(queueNum)),
	).Run()
	exist = err == nil
	logrus.WithFields(logrus.Fields{
		"chain_name": chainName,
		"protocol": protocol,
		"queue_num": queueNum,
		"exist": exist,
	}).Debug("nfqueue rule exist checked")
	return
}
