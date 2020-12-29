package policy

import (
	"io/ioutil"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
	"gopkg.in/yaml.v2"
)

type yamlPolicies struct {
	Policies []struct {
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
}

// ParseSecurityPolicy return the information slice of policy.
func ParseSecurityPolicy(path string) (policies Policies, err error) {
	pathField := logrus.WithField("path", path)
	pathField.Debug("trying to parse security policy")

	var rawPolicyData []byte
	rawPolicyData, err = ioutil.ReadFile(path)
	if err != nil {
		pathField.WithField("error", err).Debug("failed to parse security policy")
		return
	}

	var yamlData yamlPolicies
	err = yaml.Unmarshal(rawPolicyData, &yamlData)
	if err != nil {
		pathField.WithField("error", err).Debug("failed to parse security policy")
		return
	}

	// Make Policies
	var parsedPolicies Policies
	for _, yamlPolicy := range yamlData.Policies {
		var parsedPolicy Policy
		parsedPolicy.Container = &container.Container{
			Name: yamlPolicy.Container.Name,
			ID: yamlPolicy.Container.ID,
		}
		for _, yamlCommunication := range yamlPolicy.Communications {
			var communication Communication
			for _, yamlProcess := range yamlCommunication.Processes {
				communication.Processes = append(communication.Processes, &proc.Process{
					Executable: yamlProcess.Executable,
					Path: yamlProcess.Path,
				})
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
				if !strings.Contains(yamlSocket.RemoteIP, "/") {
					yamlSocket.RemoteIP = yamlSocket.RemoteIP + "/32"
				}
				_, socket.RemoteIP, _ = net.ParseCIDR(yamlSocket.RemoteIP)
				communication.Sockets = append(communication.Sockets, socket)
			}
			parsedPolicy.Communications = append(parsedPolicy.Communications, &communication)
		}
		parsedPolicies = append(parsedPolicies, &parsedPolicy)
	}

	pathField.WithField("parsed_policies", parsedPolicies).Debug("security policy parsed")
	return parsedPolicies, err
}
