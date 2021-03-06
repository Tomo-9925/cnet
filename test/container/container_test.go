package container_test

import (
	"testing"

	"github.com/tomo-9925/cnet/pkg/container"
)

func TestContainerEqual(t *testing.T) {
	var testContainers map[string]*container.Container = map[string]*container.Container{
		"hoge": {Name: "/hoge", ID: "25f561f3d0812dd6c1d97bb72d99a24437fedbe985c776896ccb328253ff7d90"},
		"fuga": {Name: "/fuga", ID: "f977b4e21a57cb2ecb5d0954eac55ec018f0f5939e8cae4494c3cd996ee945fe"},
		"shortHoge": {ID: "25f56"},
		"nameOnlyHoge": {Name: "hoge"},
		"fugaHavingHogeID": {Name: "fuga", ID: "25f56"},
	}

	if testContainers["hoge"].Equal(testContainers["fuga"]) {
		t.Error("expected hoge container equal fuga container but actual hoge container not equal fuga container")
	}
	if !testContainers["hoge"].Equal(testContainers["shortHoge"]) {
		t.Error("expected hoge container not equal short hoge container but actual hoge container equal short hoge container")
	}
	if !testContainers["hoge"].Equal(testContainers["nameOnlyHoge"]) {
		t.Error("expected hoge container not equal name only hoge container but actual hoge container equal name only hoge container")
	}
	if !testContainers["hoge"].Equal(testContainers["fugaHavingHogeID"]) {
		t.Error("expected hoge container not equal fuga having hoge id container but actual hoge container equal fuga having hoge id container")
	}
	if testContainers["fuga"].Equal(testContainers["fugaHavingHogeID"]) {
		t.Error("expected fuga container equal fuga having hoge id container but actual fuga container not equal fuga having hoge id container")
	}
}
