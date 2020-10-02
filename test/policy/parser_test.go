package parser_test

import (
	"testing"

	"github.com/google/gopacket/layers"
	cnetContainer "github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/policy"
	"github.com/tomo-9925/cnet/pkg/proc"
)

const (
	// Policy settings
	policyPath string = "./netcat_test_policy.yml"
)

var (
	// Policy data
	assumedPoliciesData policy.Policies = policy.Policies{
		&policy.Policy{
			Container: &cnetContainer.Container{Name: "cnet_netcat_test"},
			Communications: []*policy.Communication{
				&policy.Communication{
					Processes: []*proc.Process{
						&proc.Process{
							Executable: "nc",
							Path: "/usr/bin/nc",
						},
					},
					Sockets: []*policy.Socket{
						&policy.Socket{
							Protocol:  layers.LayerTypeTCP,
							LocalPort: 80,
						},
					},
				},
			},
		},
	}

	// // Docker Engine API settings
	// ctx context.Context = context.Background()
	// netcatContainerName string = "cnet_netcat_test"
	// netcatImage string = "docker.io/subfuzion/netcat"
	// netcatContainerConfig *container.Config = types.ContainerCreateConfig{
	// 	Name: netcatContainerName,
	// 	Config: &container.Config{
	// 		Image: netcatImage,
	// 		Cmd: []string{"158.217.2.147", "80"},
	// 	},
	// }.Config
)

func TestParseSecurityPolicy(t *testing.T) {
	// Compare security policy
	policies, err := policy.ParseSecurityPolicy(policyPath)
	if err != nil {
		t.Error(err)
	}
}
