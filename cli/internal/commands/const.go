package commands

import "github.com/spf13/cobra"

const (
	appName         = "xipher"
	xipherKeyPrefix = "XK_"
	xipherTxtPrefix = "XT_"
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

	// Encrypt String Command
	encryptTxtCmd *cobra.Command

	// Encrypt File Command
	encryptFileCmd *cobra.Command

	// Decrypt Command
	decryptCmd *cobra.Command

	// Decrypt String Command
	decryptTxtCmd *cobra.Command

	// Decrypt File Command
	decryptFileCmd *cobra.Command
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

	// Ignore Password Policy Check Flag
	ignorePasswordCheckFlag = flagDef{
		name:      "ignore",
		shorthand: "i",
		usage:     "Ignores the password policy check",
	}

	// Key Flag
	keyFlag = flagDef{
		name:      "key",
		shorthand: "k",
		usage:     "Specify a key string",
	}

	// Ciphertext Flag
	ciphertextFlag = flagDef{
		name:      "ciphertext",
		shorthand: "c",
		usage:     "Specify the ciphertext",
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
