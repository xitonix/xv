package main

import (
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/xitonix/xv/commands"
)

const (
	appName = "xv"
)

// Version build flags
var (
	version string
)

func main() {
	app := kingpin.New(appName, `A CLI tool to encrypt & decrypt data using AES-256 algorithm with command piping support.`)
	if version == "" {
		version = "edge_v1.0"
	}
	app.Version(fmt.Sprintf("%s %s", appName, version))
	commands.SetupAll(app)

	log.SetFlags(0)
	if _, err := app.Parse(os.Args[1:]); err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("\n%s %s%s%s", commands.EmojiFail, commands.ColourRed, err, commands.ColourReset))
	}
}
