package proc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/docker"
)

// Process is information about process needed to analyze communications of container.
type Process struct {
	ID               int
	Executable, Path string
}

func (p *Process)String() string {
	return fmt.Sprintf("{ID:%d Executable:%s Path:%s}", p.ID, p.Executable, p.Path)
}
func (p *Process)Hash() string{
	return fmt.Sprintf("%X",p.ID)
}

// Equal reports whether c and x are the same process.
func (p *Process)Equal(x *Process) bool {
	return (p.Path != "" && x.Path != "" && p.Path == x.Path) || ( p.Executable != "" && x.Executable != "" && p.Executable == x.Executable)
}

// IdentifyProcessOfContainer returns Process of container from Socket and Container and Packet.
func IdentifyProcessOfContainer(socket *Socket, container *container.Container, packet *gopacket.Packet) (process *Process, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_socket": socket,
		"communicated_container": container,
	})
	argFields.Debug("trying to identify process of container")

	if cacheRawData, exist := SocketCache.Get(socket.Hash()); exist {
		var ok bool
		process, ok = cacheRawData.(*Process)
		if ok {
			argFields.WithField("identified_process", process).Debug("the process identified")
			return
		}
		process = nil
	}

	switch socket.Protocol {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		var inode uint64
		inode, err = SearchInodeFromNetOfPid(socket, container.Pid)
		if err != nil {
			argFields.WithField("error", err).Debug("failed to indentify process of container")
			return
		}
		process, err = SearchProcessOfContainerFromInode(container, socket, inode)
		if err != nil {
			argFields.WithField("warn", err).Debug("could not identify the process by tcp or udp")
			break
		}
		argFields.WithField("identified_process", process).Debug("the process identified")
		SocketCache.Set(socket.Hash(), process, 0)
		return
	}

	// detect the process of raw socket
	var inodes []uint64
	inodes, err = RetrieveAllInodeFromRawOfPid(container.Pid, socket)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to identify process of container")
		return
	}
	suspiciousProcesses := map[Process]struct{}{}
	for _, inode := range inodes {
		var suspiciousProcess *Process
		suspiciousProcess, err = SearchProcessOfContainerFromInode(container, socket, inode)
		if err != nil {
			argFields.WithField("error", err).Trace("process not found")
			continue
		}
		suspiciousProcesses[*suspiciousProcess] = struct{}{}
	}
	if len(suspiciousProcesses) == 1 {
		for suspiciousProcess := range suspiciousProcesses {
			process = &suspiciousProcess
			argFields.WithField("identified_process", process).Debug("the process identified")
			return
		}
	}
	var identifier uint16
	identifier, err = CheckIdentifierOfICMP(socket, packet)
	if err == nil {
		identifierStr := strconv.FormatUint(uint64(identifier), 10)
		for suspiciousProcess := range suspiciousProcesses {
			if NSpidExists(suspiciousProcess.ID, identifierStr) {
				process = &suspiciousProcess
				argFields.WithField("identified_process", process).Debug("the process identified")
				return
			}
		}
	}

	result := make([]*Process, 0, len(suspiciousProcesses))
	for suspiciousProcess := range suspiciousProcesses {
		result = append(result, &suspiciousProcess)
	}
	argFields.WithField("suspicious_processes", result).Warn("multiple processes detected")

	err = errors.New("the process not found")
	argFields.WithField("error", err).Debug("failed to indentify process of container")
	return
}

// MakeRetrieveSocketEntryFunction return the function that retrieve socket entry of specific process id and protocol.
func MakeRetrieveSocketEntryFunction(targetSocket *Socket, pid int) (retrieveFunction func() ([3]string, bool), err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_socket": targetSocket,
		"pid": pid,
	})
	argFields.Debug("trying to make the function that retrieve socket entry")

	// dealing with ipv4-mapped ipv6 address
	var netFilePath string
	switch targetSocket.Protocol {
	case layers.LayerTypeTCP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "tcp6")
	case layers.LayerTypeUDP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "udp6")
	default:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "raw6")
	}

	// dealing with ipv4-mapped ipv6 address
	var communicationEntries []byte
	communicationEntries, err = ioutil.ReadFile(netFilePath)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to search inode from net of pid")
		return
	}
	communicationEntries = communicationEntries[bytes.Index(communicationEntries, []byte("\n"))+1:]
	if targetSocket.LocalIP.To4() != nil {
		var v4Entries []byte
		v4Entries, err = ioutil.ReadFile(netFilePath[:len(netFilePath)-1])
		if err != nil {
			argFields.WithField("error", err).Debug("failed to search inode from net of pid")
			return
		}
		v4Entries = v4Entries[bytes.Index(v4Entries, []byte("\n"))+1:]
		communicationEntries = bytes.Join([][]byte{communicationEntries, v4Entries}, []byte{})
	}

	entryScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&communicationEntries))))
	retrieveFunction = func() (entry [3]string, exist bool) {
		argFields.Debugln("trying to retrieve entry of socket")

		for exist = entryScanner.Scan(); exist; exist = entryScanner.Scan() {
			columnScanner := bufio.NewScanner(strings.NewReader(entryScanner.Text()))
			columnScanner.Split(bufio.ScanWords)
			argFields.WithFields(logrus.Fields{"entry": entryScanner.Text(), "net_file_path": netFilePath}).Trace("checking the entry")
			checkColumn:
			for columnCounter := 0; columnScanner.Scan(); columnCounter++ {
				switch columnCounter {
				case localAddressColumn:
					entry[0] = columnScanner.Text()
				case remoteAddressColumn:
					entry[1] = columnScanner.Text()
				case inodeColumn:
					entry[2] = columnScanner.Text()
					break checkColumn
				}
			}
			entryFields := logrus.Fields{
				"net_file_path": netFilePath,
				"local_address": entry[0],
				"rem_address": entry[1],
				"inode": entry[2],
			}
			if entry[2] == "0" {
				argFields.WithFields(entryFields).Trace("detect inode == 0 entry")
				continue
			}
			argFields.WithFields(entryFields).Debug("entry retrieved")
			return
		}
		argFields.Debugln("entry not exist")
		return
	}

	argFields.Debugln("the function that retrieve socket entry made")
	return
}

// SearchInodeFromNetOfPid returns inode from net of a specific pid in proc filesystem.
func SearchInodeFromNetOfPid(targetSocket *Socket, pid int) (inode uint64, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_socket": targetSocket,
		"pid": pid,
	})
	argFields.Debug("trying to search inode from net of pid")

	// Make local_address and rem_address string
	socketLocalPort := fmt.Sprintf("%04X", targetSocket.LocalPort)
	socketRemoteAddr := fmt.Sprintf("%s:%04X", IPtoa(targetSocket.RemoteIP), targetSocket.RemotePort)
	argFields.WithFields(logrus.Fields{
		"socket_local_port_string": socketLocalPort,
		"socket_remote_address_string": socketRemoteAddr,
		}).Trace("the strings for comparison created")

	// Search entry of net socket
	var retrieveSocketEntry func() ([3]string, bool)
	retrieveSocketEntry, err = MakeRetrieveSocketEntryFunction(targetSocket, pid)
	if err != nil {
		return
	}
	for entry, exist := retrieveSocketEntry(); exist; entry, exist = retrieveSocketEntry() {
		if !strings.HasSuffix(entry[0], socketLocalPort) {
			argFields.WithField("net_local_port", entry[0]).Trace("the entry skipped")
			continue
		}
		// server process makes 00000000:0000 rem_address entry. remote address is a possible IPv4-mapped IPv6 address.
		if strings.HasSuffix(entry[1], "0000") || strings.HasSuffix(entry[1], socketRemoteAddr) {
			inode, err = strconv.ParseUint(entry[2], 10, 64)
			argFields.WithField("socket_inode", inode).Debug("inode found")
			return
		}
	}
	err = errors.New("applicable communication entry not found")
	argFields.WithField("error", err).Debug("failed to search inode from net of pid")
	return
}

// RetrieveAllInodeFromRawOfPid return all inodes of specific process id.
func RetrieveAllInodeFromRawOfPid(pid int, targetSocket *Socket) (allInode []uint64, err error) {
	argFields := logrus.WithField("process_id", pid)
	argFields.Debug("trying to retrieve all inode from net of pid")

	var retrieveSocketEntry func() ([3]string, bool)
	retrieveSocketEntry, err = MakeRetrieveSocketEntryFunction(targetSocket, pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve all inode from net of pid")
		return
	}
	for entry, exist := retrieveSocketEntry(); exist; entry, exist = retrieveSocketEntry(){
		var inode uint64
		inode, err = strconv.ParseUint(entry[2], 10, 64)
		allInode = append(allInode, inode)
	}
	argFields.WithField("all_inode", allInode).Debug("all inode retrieved")
	return
}

// SearchProcessOfContainerFromInode return Process struct of the process that have specific socket inode.
func SearchProcessOfContainerFromInode(communicatedContainer *container.Container, targetSocket *Socket, inode uint64) (process *Process, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"communicated_container": communicatedContainer,
		"inode": inode,
	})
	argFields.Debug("trying to search process of container from inode")

	if targetSocket.Protocol == layers.LayerTypeUDP && targetSocket.RemotePort == 53 && SocketInodeExists(docker.PID, inode) {
		process, err = MakeProcessStruct(docker.PID)
		if err != nil {
			argFields.WithField("error", err).Debug("failed to search process of container from inode")
			return
		}
		argFields.WithField("process", process).Debug("process exists")
		return
	}

	var containerdShimPid int
	containerdShimPid, err = RetrievePPID(communicatedContainer.Pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to search process of container from inode")
		return
	}
	argFields.WithField("pid_of_containerd_shim", containerdShimPid).Trace("pid of containered-shim retrieved")
	var childPIDs []int
	childPIDs, err = RetrieveChildPIDs(containerdShimPid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to search process of container from inode")
		return
	}

	// Check inode of pids
	for _, pid := range childPIDs {
		if SocketInodeExists(pid, inode) {
			process, err = MakeProcessStruct(pid)
			if err != nil {
				argFields.WithField("error", err).Debug("failed to search process of container from inode")
				return
			}
			argFields.WithField("process", process).Debug("process exists")
			return
		}
	}
	err = errors.New("process not found")
	argFields.WithField("error", err).Debug("failed to search process of container from inode")
	return
}

// MakeProcessStruct return Process struct of specified pid.
func MakeProcessStruct(pid int) (process *Process, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to make process struct")

	var executable, path string
	executable, err = RetrieveProcessName(pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to make process struct")
		return
	}
	argFields.WithField("retrieved_executable", executable).Trace("executable retrieved")
	path, err = RetrieveProcessPath(pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to make process struct")
		return
	}
	argFields.WithField("retrieved_path", path).Trace("path retrieved")

	process = &Process{pid, executable, path}
	argFields.WithField("process", process).Debug("the process struct made")
	return
}

// RetrievePPID gets the PPID from stat of proc filesystem.
func RetrievePPID(pid int) (ppid int, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve ppid")

	var file []byte
	file, err = ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "stat"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve ppid")
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	for i := 0; scanner.Scan(); i++ {
		if i == 3 {
			ppid, err = strconv.Atoi(scanner.Text())
			break
		}
	}
	argFields.WithField("retrieved_ppid", ppid).Debug("the ppid retrieved")
	return
}

// makeChildPIDMap return child pid map (the key is pid. the value is child pid slice).
// func makeChildPIDMap() (result map[int][]int) {
// 	logrus.Debugln("trying to make child pid map")
// 	result = make(map[int][]int)

// 	files, err := ioutil.ReadDir(procPath)
// 	if err != nil {
// 		return
// 	}

// 	for _, file := range files {
// 		var pid, ppid int
// 		fileName := file.Name()
// 		if fileName[0] < '0' || fileName[0] > '9' {
// 			continue
// 		}
// 		pid, err = strconv.Atoi(fileName)
// 		if err != nil {
// 			continue
// 		}
// 		ppid, err = RetrievePPID(pid)
// 		if err != nil {
// 			continue
// 		}
// 		result[ppid] = append(result[ppid], pid)
// 	}

// 	logrus.WithField("child_pid_map", result).Debug("child pid map made")
// 	return
// }

// retrieveChildren gets the child processes from children of process filesystem.
func retrieveChildren(pid int) (result []int, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve the children")

	pidStr := strconv.Itoa(pid)
	var file []byte
	file, err = ioutil.ReadFile(filepath.Join(procPath, pidStr, "task", pidStr, "children"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve the children")
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		var childPid int
		childPid, err = strconv.Atoi(scanner.Text())
		if err != nil {
			argFields.WithField("error", err).Debug("failed to retrieve the children")
			return
		}
		result = append(result, childPid)
	}

	argFields.WithField("children", result).Debug("the children retrieved")
	return
}

// RetrieveChildPIDs gets recursively child PIDs from children of proc filesystem.
func RetrieveChildPIDs(pid int) (childPIDSlice []int, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve child pids")

	var searchPIDStack pidStack

	// procfs children method (not exactly)
	var retrievedChildren []int
	for {
		retrievedChildren, err = retrieveChildren(pid)
		if err != nil {
			argFields.WithField("retrieved_child_pids", childPIDSlice).Debug("failed to retrieve the child pids")
			return
		}
		searchPIDStack.Push(retrievedChildren...)
		if searchPIDStack.Len() == 0 {
			break
		}
		pid = searchPIDStack.Pop()
		childPIDSlice = append(childPIDSlice, pid)
	}

	// python psutil method (take a lot of time)
	// childPIDMap := makeChildPIDMap()
	// searchPIDStack.Push(childPIDMap[pid]...)
	// for searchPIDStack.Len() != 0 {
	// 	currentPID := searchPIDStack.Pop()
	// 	childPIDSlice = append(childPIDSlice, currentPID)
	// 	searchPIDStack.Push(childPIDMap[currentPID]...)
	// }

	argFields.WithField("retrieved_child_pids", childPIDSlice).Debug("the child pids retrieved")
	return
}

// SocketInodeExists reports whether the process has socket inode.
func SocketInodeExists(pid int, inode uint64) (exist bool) {
	argFields := logrus.WithFields(logrus.Fields{
		"pid": pid,
		"socket_inode": inode,
	})
	argFields.Debug("trying to check whether the process has socket inode")

	fdDirPath := filepath.Join(procPath, strconv.Itoa(pid), "fd")
	fdFiles, err := ioutil.ReadDir(fdDirPath)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to check whether the process has socket inode")
		return
	}
	for _, fdFile := range fdFiles {
		linkContent, err := os.Readlink(filepath.Join(fdDirPath, fdFile.Name()))
		if err != nil {
			argFields.WithField("error", err).Debug("failed to check whether the process has socket inode")
			return
		}
		if strings.HasPrefix(linkContent, "socket") && linkContent[8:len(linkContent)-1] == strconv.FormatUint(inode, 10) {
			exist = true
			argFields.Debug("socket inode exists")
			return
		}
	}
	argFields.WithField("error", "file descriptor with the socket inode not found").Debug("failed to check whether the process has socket inode")
	return
}

// NSpidExists reports whether the process has namespace process id.
func NSpidExists(pid int, nspidStr string) (result bool) {
	argFields := logrus.WithFields(logrus.Fields{
		"pid": pid,
		"nspid": nspidStr,
	})
	argFields.Debug("trying to check whether the process has namespace process id")

	var file []byte
	file, err := ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "status"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to check whether the process has nspid")
		return
	}
	rowScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	for rowScanner.Scan() {
		rowText := rowScanner.Text()
		if strings.HasPrefix(rowText, "NSpid") {
			result = strings.HasSuffix(rowText, nspidStr)
			break
		}
	}

	argFields.WithField("error", "nspid not found").Debug("failed to check whether the process has namespace process id")
	return
}

// RetrieveProcessName gets the process name from stat of process filesystem.
func RetrieveProcessName(pid int) (executable string, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve process name")

	var commFile []byte
	commFile, err = ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "comm"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve process name")
		return
	}
	executable = strings.TrimSuffix(*(*string)(unsafe.Pointer(&commFile)), "\n")
	argFields.WithField("executable", executable).Debug("the process name retrieved")
	return
}

// RetrieveProcessPath gets the process path from stat of process filesystem.
func RetrieveProcessPath(pid int) (path string, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve process path")
	path, err = os.Readlink(filepath.Join(procPath, strconv.Itoa(pid), "exe"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve process path")
		return
	}
	argFields.Debug("the process path retrieved")
	return
}
