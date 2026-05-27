package main

import (
	"flag"
	"fmt"
)

func runEvidence(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp evidence <view>")
	}
	fs := flag.NewFlagSet("evidence "+args[0], flag.ContinueOnError)
	filePath := fs.String("file", "", "local evidence bundle path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "view":
		return viewEvidenceBundleFile(*filePath)
	default:
		return fmt.Errorf("usage: whcp evidence <view>")
	}
}
