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

func parseYAMLPolicyList(path string) (parsedPolicyList []*Policy, err error) {
	pathField := logrus.WithField("path", path)
	pathField.Debug("trying to parse yaml policy list")

	var rawPolicyData []byte
	rawPolicyData, err = ioutil.ReadFile(path)
	if err != nil {
		pathField.WithField("error", err).Debug("failed to parse yaml policy list")
		return
	}

	var yamlData yamlPolicies
	err = yaml.Unmarshal(rawPolicyData, &yamlData)
	if err != nil {
		pathField.WithField("error", err).Debug("failed to parse yaml policy list")
		return
	}

	// Make Policies
	parsedPolicyList = make([]*Policy, len(yamlData.Policies))
	for i, yamlPolicy := range yamlData.Policies {
		parsedPolicy := &Policy{Container: &container.Container{
			Name: yamlPolicy.Container.Name,
			ID: yamlPolicy.Container.ID,
		}}
		parsedPolicyList[i] = parsedPolicy
		parsedPolicy.Communications = make([]*Communication, len(yamlPolicy.Communications))
		for j, yamlCommunication := range yamlPolicy.Communications {
			parsedCommunication := &Communication{}
			parsedPolicy.Communications[j] = parsedCommunication
			parsedCommunication.Processes = make([]*proc.Process, len(yamlCommunication.Processes))
			for k, yamlProcess := range yamlCommunication.Processes {
				parsedCommunication.Processes[k] = &proc.Process{
					Executable: yamlProcess.Executable,
					Path: yamlProcess.Path,
				}
			}
			parsedCommunication.Sockets = make([]*Socket, len(yamlCommunication.Sockets))
			for k, yamlSocket := range yamlCommunication.Sockets {
				parsedSocket := &Socket{
					LocalPort: yamlSocket.LocalPort,
					RemotePort: yamlSocket.RemotePort,
				}
				parsedCommunication.Sockets[k] = parsedSocket
				protocol := strings.ToLower(yamlSocket.Protocol)
				switch protocol {
				case "tcp":
					parsedSocket.Protocol = layers.LayerTypeTCP
				case "udp":
					parsedSocket.Protocol = layers.LayerTypeUDP
				case "icmpv4":
					parsedSocket.Protocol = layers.LayerTypeICMPv4
				}
				if !strings.Contains(yamlSocket.RemoteIP, "/") {
					var appendString string = "/32"
					if strings.Contains(yamlSocket.RemoteIP, ":") {
						appendString = "/128"
					}
					yamlSocket.RemoteIP = strings.Join([]string{yamlSocket.RemoteIP, appendString}, "")
				}
				_, parsedSocket.RemoteIP, _ = net.ParseCIDR(yamlSocket.RemoteIP)
			}
		}
	}
	return
}

// Read returns the Policies of the specified YAML file path.
func Read(path string) (policies *Policies, err error) {
	pathField := logrus.WithField("path", path)
	pathField.Debug("trying to read the policy")

	var parsedPolicyList []*Policy
	parsedPolicyList, err = parseYAMLPolicyList(path)
	if err != nil {
		pathField.WithField("error", err).Debug("failed to read the policy")
		return
	}
	policies = &Policies{Path: path, List: parsedPolicyList}

	pathField.WithField("policies", policies).Debug("the policy read")
	return
}
