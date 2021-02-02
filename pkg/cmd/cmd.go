package cmd

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
)

// Execute will execute command
func Execute(cmd string, arg []string) (output []byte, erroutput []byte, err error) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd := exec.Command(cmd, arg...)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()

		output := stdout.Bytes()
		erroutput := stderr.Bytes()

		if err != nil {
			return output, erroutput, err
		}

		return output, erroutput, nil
	}

	return nil, nil, fmt.Errorf("Can't Execute this on a machine different than Linux or Darwin")
}
