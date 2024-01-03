package commands

import (
	"encoding/base32"
	"fmt"
	"os"

	"github.com/fatih/color"
)

func exitOnError(err error) {
	fmt.Fprintln(os.Stderr, color.RedString(err.Error()))
	erroredExit()
}

func exitOnErrorWithMessage(errMessage string) {
	fmt.Fprintln(os.Stderr, color.RedString(errMessage))
	erroredExit()
}

func erroredExit() {
	os.Exit(1)
}

func safeExit() {
	os.Exit(0)
}

func encode(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func decode(str string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
}
