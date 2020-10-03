package policy

import (
	"io/ioutil"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/k0kubun/pp"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
	"gopkg.in/yaml.v2"
)

type yamlPolicies []struct {
	Container struct {
		Name string `yaml:"name"`
		ID string `yaml:"id"`
	}
	Communications []struct {
		Processes []struct {
			Executable string `yaml:"executable"`
			Path string `yaml:"path"`
		}
		Sockets []struct {
			Protocol string `yaml:"protocol"`
			LocalPort uint16 `yaml:"local_port"`
			RemoteIP string `yaml:"remote_ip"`
			RemotePort uint16 `yaml:"remote_port"`
		}
	}
}

// ParseSecurityPolicy return the information slice of policy.
func ParseSecurityPolicy(path string) (policies Policies, err error) {
	// Read security policies
	var rawPolicyData []byte
	rawPolicyData, err = ioutil.ReadFile(path)
	if err != nil {
		return policies, err
	}

	// Parse to yamlPolicies
	var yamlData yamlPolicies
	err = yaml.Unmarshal(rawPolicyData, &yamlData)
	if err != nil {
		return policies, err
	}
	pp.Println(yamlData)

	// Make Policies
	for _, yamlPolicy := range yamlData {
		var policy *Policy
		policy.Container = &container.Container{
			Name: yamlPolicy.Container.Name,
			ID: yamlPolicy.Container.ID,
		}
		for _, yamlCommunication := range yamlPolicy.Communications {
			var communication *Communication
			for _, yamlProcess := range yamlCommunication.Processes {
				process := &proc.Process{
					Executable: yamlProcess.Executable,
					Path: yamlProcess.Path,
				}
				communication.Processes = append(communication.Processes, process)
			}
			for _, yamlSocket := range yamlCommunication.Sockets {
				socket := &Socket{
					LocalPort: yamlSocket.LocalPort,
					RemotePort: yamlSocket.RemotePort,
				}
				protocol := strings.ToLower(yamlSocket.Protocol)
				switch protocol {
				case "tcp":
					socket.Protocol = layers.LayerTypeTCP
				case "udp":
					socket.Protocol = layers.LayerTypeUDP
				case "icmpv4":
					socket.Protocol = layers.LayerTypeICMPv4
				}
				if strings.Contains(yamlSocket.RemoteIP, "/") {
					_, socket.RemoteIP, err = net.ParseCIDR(yamlSocket.RemoteIP)
					if err != nil {
						return policies, err
					}
				} else {
					socket.RemoteIP.IP = net.ParseIP(yamlSocket.RemoteIP)
				}
				communication.Sockets = append(communication.Sockets, socket)
			}
			policy.Communications = append(policy.Communications, communication)
		}
		policies = append(policies, policy)
	}

	return policies, err
}
