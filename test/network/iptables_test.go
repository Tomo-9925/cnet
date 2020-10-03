package network_test

import (
	"testing"

	"github.com/tomo-9925/cnet/pkg/network"
)

const (
	chainName string = "DOCKER-USER"
	ruleNum   uint16 = 1
	protocol  string = "all"
	queueNum  uint16 = 2
)

func TestNFQueueRule(t *testing.T) {
	err := network.InsertNFQueueRule(chainName, protocol, ruleNum, queueNum)
	if err != nil {
		t.Fatal(err)
	}
	if !network.ExistsNFQueueRule(chainName, protocol, queueNum) {
		t.Fatal("couldn't append nfqueue rule")
	}
	err = network.DeleteNFQueueRule(chainName, protocol, queueNum)
	if err != nil {
		t.Fatal(err)
	}
	if network.ExistsNFQueueRule(chainName, protocol, queueNum) {
		t.Fatal("couldn't delete nfqueue rule")
	}
}
