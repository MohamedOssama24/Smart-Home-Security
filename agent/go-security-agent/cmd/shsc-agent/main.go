// Command shsc-agent is the Smart Home Security Check local security agent.
package main

import (
	"os"

	"shsc/agent/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
