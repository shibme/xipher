package commands

import "github.com/spf13/cobra"

const (
	appName = "xipher"
)

var (
	// Xipher Command
	xipherCmd *cobra.Command

	// Version Command
	versionCmd *cobra.Command

	// Keygen Command
	keygenCmd *cobra.Command

	// Encrypt Command
	encryptCmd *cobra.Command

	// Decrypt Command
	decryptCmd *cobra.Command
)

type flagDef struct {
	name      string
	shorthand string
	usage     string
}

var (

	// Version Flag
	versionFlag = flagDef{
		name:      "version",
		shorthand: "v",
		usage:     "Shows version info",
	}

	// Password Flag
	passwordFlag = flagDef{
		name:      "password",
		shorthand: "p",
		usage:     "Specify a password",
	}

	// Key Flag
	keyFlag = flagDef{
		name:      "key",
		shorthand: "k",
		usage:     "Specify a key string",
	}

	// File Flag
	fileFlag = flagDef{
		name:      "file",
		shorthand: "f",
		usage:     "Specify file path",
	}

	// Out Flag
	outFlag = flagDef{
		name:      "out",
		shorthand: "o",
		usage:     "Specify an output file path",
	}

	// Compress Flag
	compressFlag = flagDef{
		name:      "compress",
		shorthand: "c",
		usage:     "Enable compression as the data is encrypted",
	}
)
