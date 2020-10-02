package proc_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/tomo-9925/cnet/pkg/proc"
)

func TestIPtoa(t *testing.T) {
	testIP := net.ParseIP("192.168.11.1")
	testIPStr := proc.IPtoa(testIP)
	if (proc.HostByteOrder == binary.LittleEndian && testIPStr != "010BA8C0") ||
	(proc.HostByteOrder == binary.BigEndian && testIPStr != "C0A80B01") {
		t.Fatal("couldn't convert ip address")
	}
}
