package main

import (
	"os"

	"github.com/pjbgf/zaz/cmd/cli"
)

func main() {
	err := cli.Run(os.Stdout, os.Args)
	if err != nil {
		os.Exit(1)
	}
}
