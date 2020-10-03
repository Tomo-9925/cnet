package policy_test

import (
	"testing"

	"github.com/k0kubun/pp"
	"github.com/tomo-9925/cnet/pkg/policy"
)

const (
	policyPath string = "./netcat_test_policy"
)

func TestParseSecurityPolicy(t *testing.T) {
	policies, err := policy.ParseSecurityPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	pp.Println(policies)
}
