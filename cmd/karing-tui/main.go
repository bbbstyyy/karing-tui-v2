package main

import (
	"os"

	"github.com/bbbstyyy/karing-tui-v2/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr))
}
