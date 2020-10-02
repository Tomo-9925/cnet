package proc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// HostByteOrder refers to how bytes are arranged when referring to the computer architecture of an OS
var HostByteOrder binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		HostByteOrder = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		HostByteOrder = binary.BigEndian
	default:
		logrus.Fatalln("native endianness not determined")
	}
}

// IPtoa converts IP into string for net
func IPtoa(ip net.IP) (ipStr string) {
	ipv4 := ip.To4()
	// IPv6 not supported
	if ipv4 == nil {
		return
	}

	ipv4Int := big.NewInt(0)
	ipv4Int.SetBytes(ipv4)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, HostByteOrder, uint32(ipv4Int.Uint64()))
	if err != nil {
		return
	}
	ipStr = fmt.Sprintf("%X", buf.Bytes())
	return
}
