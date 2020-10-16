package container_test

import (
	"testing"

	"github.com/tomo-9925/cnet/pkg/container"
)

func TestContainerEqual(t *testing.T) {
	var testContainers map[string]*container.Container = map[string]*container.Container{
		"hoge": &container.Container{Name: "/hoge", ID: "25f561f3d0812dd6c1d97bb72d99a24437fedbe985c776896ccb328253ff7d90"},
		"fuga": &container.Container{Name: "/fuga", ID: "f977b4e21a57cb2ecb5d0954eac55ec018f0f5939e8cae4494c3cd996ee945fe"},
		"shortHoge": &container.Container{ID: "25f56"},
		"nameOnlyHoge": &container.Container{Name: "hoge"},
		"fugaHavingHogeID": &container.Container{Name: "fuga", ID: "25f56"},
	}

	if testContainers["hoge"].Equal(testContainers["fuga"]) {
		t.Error("hoge container equal fuga container")
	}
	if !testContainers["hoge"].Equal(testContainers["shortHoge"]) {
		t.Error("hoge container not equal short hoge container")
	}
	if !testContainers["hoge"].Equal(testContainers["nameOnlyHoge"]) {
		t.Error("hoge container not equal name only hoge container")
	}
	if !testContainers["hoge"].Equal(testContainers["fugaHavingHogeID"]) {
		t.Error("hoge container not equal fuga having hoge id container")
	}
	if testContainers["fuga"].Equal(testContainers["fugaHavingHogeID"]) {
		t.Error("fuga container equal fuga having hoge id container")
	}
}
