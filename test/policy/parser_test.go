package policy_test

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
)

var (
	// test data
	testContainerName string = "cnet_netcat_test"
	testProcessExecutable string = "nc"
	testProcessPath string = "/usr/bin/nc"
	testSocketProtocol gopacket.LayerType = layers.LayerTypeTCP
	testSocketRemoteIP net.IP = net.ParseIP("158.217.2.147")
	testSocketRemotePort uint16 = 80

  expectedPolicies policy.Policies = policy.Policies{
		List: []*policy.Policy{{
			Container: &container.Container{
				Name: testContainerName,
			},
			Communications: []*policy.Communication{{
				Processes: []*proc.Process{{
					Executable: testProcessExecutable,
					Path: testProcessPath}},
				Sockets: []*policy.Socket{{
					Protocol: testSocketProtocol,
					RemoteIP: &net.IPNet{IP: testSocketRemoteIP, Mask: net.CIDRMask(32, 32)},
					RemotePort: testSocketRemotePort}},
			}},
		}},
	}
)

func TestParseSecurityPolicy(t *testing.T) {
  var rawPolicies string = fmt.Sprintf(
`policies:
  - container:
      name: "%s"
    communications:
      - processes:
          - executable: "%s"
            path: "%s"
        sockets:
          - protocol: %s
            remote_ip: %s
            remote_port: %d
`,
    testContainerName,
    testProcessExecutable, testProcessPath,
    testSocketProtocol.String(), testSocketRemoteIP.String(), testSocketRemotePort)

	// Make YAML file
	tmpPolicyFile, err := ioutil.TempFile("", "testPolicy.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpPolicyFile.Close()
	defer os.Remove(tmpPolicyFile.Name())
	if _, err := tmpPolicyFile.Write( *(*[]byte)(unsafe.Pointer(&rawPolicies)) ); err != nil {
		t.Fatal(err)
	}

	// Parse policies
	parsedPolicies, err := policy.Read(tmpPolicyFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(parsedPolicies.List, expectedPolicies.List); diff != "" {
		t.Error("policies differs:", diff)
	}
}

