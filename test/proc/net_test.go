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
		t.Fatal("couldn't convert ipv4 address")
	}

	testIP = net.ParseIP("fe80::250:56ff:fe8a:9e41")
	testIPStr = proc.IPtoa(testIP)
	if (proc.HostByteOrder == binary.LittleEndian && testIPStr != "000080FE00000000FF565002419E8AFE") ||
	(proc.HostByteOrder == binary.BigEndian && testIPStr != "FE80000000000000025056FFFE8A9E41") {
		t.Fatal("couldn't convert ipv6 address")
	}
}
