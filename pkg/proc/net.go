package proc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
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
	logrus.WithField("host_byte_order", HostByteOrder).Debug("host byte order checked")
}

// IPtoa converts IP address into string for net
func IPtoa(ip net.IP) (ipStr string) {
	argFields := logrus.WithField("ip_address", ip)
	argFields.Debug("trying to convert the ip address into string for net")

	ipv4 := ip.To4()
	if ipv4 == nil {
		ipBytes := ([]byte)(ip)
		var ipStrs []string = make([]string, 4)
		for i := 0; i < 16 ; i += 4 {
			tmpInt := big.NewInt(0)
			tmpInt.SetBytes(ipBytes[i:i+4])
			buf := new(bytes.Buffer)
			err := binary.Write(buf, HostByteOrder, uint32(tmpInt.Uint64()))
			if err != nil {
				argFields.WithFields(logrus.Fields{
					"error": err,
					"tmp_int": tmpInt,
					}).Debug("trying to convert ip address into string for net")
				return
			}
			ipStrs = append(ipStrs, fmt.Sprintf("%X", buf.Bytes()))
		}
		argFields.WithField("ip_address_string", ipStr).Debug("the ip address converted")
		return strings.Join(ipStrs, "")
	}

	ipv4Int := big.NewInt(0)
	ipv4Int.SetBytes(ipv4)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, HostByteOrder, uint32(ipv4Int.Uint64()))
	if err != nil {
		argFields.WithFields(logrus.Fields{
			"error": err,
			"ipv4_int": ipv4Int,
			}).Debug("trying to convert ip address into string for net")
		return
	}
	ipStr = fmt.Sprintf("%X", buf.Bytes())
	argFields.WithField("ip_address_string", ipStr).Debug("the ip address converted")
	return
}
