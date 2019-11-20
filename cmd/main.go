package main

import (
	"os"

	"github.com/pjbgf/zaz/cmd/cli"
)

func main() {
	cli.NewConsole(os.Stdout, os.Stderr, os.Exit).Run(os.Args)
}
