package proc

import "github.com/sirupsen/logrus"

type pidStack struct {
	top  *pidStackElement
	size int
}

type pidStackElement struct {
	pid  int
	next *pidStackElement
}

func (s *pidStack) Len() int {
	return s.size
}

func (s *pidStack) Push(pids ...int) {
	logrus.WithField("pid_stack", s).Debug("trying to push pid")
	for i := len(pids) - 1; i >= 0; i-- {
		s.top = &pidStackElement{pids[i], s.top}
		s.size++
		logrus.WithField("pid_stack", s).Debug("pid pushed")
	}
}

func (s *pidStack) Pop() (pid int) {
	logrus.WithField("pid_stack", s).Debug("trying to pop pid")
	if s.size > 0 {
		pid, s.top = s.top.pid, s.top.next
		s.size--
		logrus.WithField("pid_stack", s).Debug("pid poped")
		return
	}
	logrus.WithField("pid_stack", s).Debug("pid not poped")
	return -1
}
