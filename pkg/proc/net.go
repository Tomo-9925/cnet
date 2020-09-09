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

var byteOrder binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		byteOrder = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		byteOrder = binary.BigEndian
	default:
		logrus.Fatalln("Could not determine native endianness.")
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
	err := binary.Write(buf, binary.BigEndian, uint32(ipv4Int.Uint64()))
	if err != nil {
		return
	}
	ipStr = fmt.Sprintf("%X", buf.Bytes())
	return
}
