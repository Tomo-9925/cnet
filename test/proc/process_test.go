package proc_test

import (
	"os"
	"testing"

	"github.com/k0kubun/pp"
	"github.com/tomo-9925/cnet/pkg/proc"
)

func TestProcessEqual(t *testing.T) {
	var testProcesses map[string]*proc.Process = map[string]*proc.Process{
		"detectedNetcat": {ID: 9925, Executable: "nc", Path: "/usr/bin/nc"},
		"policyNetcat1": {Executable: "nc"},
		"policyNetcat2": {Path: "/usr/bin/nc"},
		"differentPathNetcat": {Executable: "nc", Path: "/usr/local/bin/nc"},
		"differentExecutableNetcat": {Executable: "telnet", Path: "/usr/bin/nc"},
	}

	if !testProcesses["policyNetcat1"].Equal(testProcesses["detectedNetcat"]) {
		t.Error("policy netcat 1 not equal detected netcat")
	}
	if !testProcesses["policyNetcat2"].Equal(testProcesses["detectedNetcat"]) {
		t.Error("policy netcat 2 not equal detected netcat")
	}
	if testProcesses["differentPathNetcat"].Equal(testProcesses["detectedNetcat"]) {
		t.Error("different path netcat equal detected netcat")
	}
	if !testProcesses["differentExecutableNetcat"].Equal(testProcesses["detectedNetcat"]) {
		t.Error("different executable netcat not equal detected netcat")
	}
}

func TestRetrievePIDFunctions(t *testing.T) {
	thisPID := os.Getpid()
	thisPPID := os.Getppid()

	thisExecutable, err := proc.RetrieveProcessName(thisPID)
  if err != nil {
    t.Error(err)
  }
	thisPath, err := proc.RetrieveProcessPath(thisPID)
  if err != nil {
    t.Error(err)
  }
	thisParentExecutable, err := proc.RetrieveProcessName(thisPPID)
  if err != nil {
    t.Error(err)
  }
	thisParentPath, err := proc.RetrieveProcessPath(thisPPID)
  if err != nil {
    t.Error(err)
  }
	pp.Println(map[string]proc.Process{
		"ThisProcess": {ID: thisPID, Executable: thisExecutable, Path:thisPath},
		"ThisParentProcess": {ID: thisPPID, Executable: thisParentExecutable, Path:thisParentPath},
	})

	retrievedPPID, err := proc.RetrievePPID(thisPID)
	if err != nil {
		t.Fatal(err)
	}
	if retrievedPPID != thisPPID {
		t.Error("retrieved ppid not equal this ppid")
	}

  // NOTE: RetrieveChildPIDs is the function for retrieving child processes of a process in a container.
  // retrievedChildPIDs, err := proc.RetrieveChildPIDs(thisPPID)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// for _, childPID := range retrievedChildPIDs {
	// 	if childPID == thisPID {
	// 		return
	// 	}
	// }
	// t.Error("retrieved child pids not contained this pid")
}
