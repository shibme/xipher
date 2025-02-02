package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
)

func exitOnError(err error, jsonFormat bool) {
	exitOnErrorWithMessage(err.Error(), jsonFormat)
}

func exitOnErrorWithMessage(errMessage string, jsonFormat bool) {
	if jsonFormat {
		errorMap := map[string]interface{}{
			"error": errMessage,
		}
		fmt.Fprintln(os.Stderr, toJsonString(errorMap))
	} else {
		fmt.Fprintln(os.Stderr, color.RedString(errMessage))
	}
	os.Exit(1)
}

func toJsonString(data interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(jsonBytes)
}
