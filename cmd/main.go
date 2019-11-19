package main

import (
	"os"

	"github.com/pjbgf/zaz/cmd/cli"
)

var onError func(err error) = func(err error) {
	os.Exit(1)
}

func main() {
	cli.Run(os.Stdout, os.Args, onError)
}
