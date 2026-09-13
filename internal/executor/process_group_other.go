//go:build !unix

package executor

import (
	"os"
	"os/exec"
)

func configureCommandCancellation(command *exec.Cmd) {
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return command.Process.Signal(os.Interrupt)
	}
}

func cleanupCommandProcesses(*exec.Cmd) error {
	return nil
}
