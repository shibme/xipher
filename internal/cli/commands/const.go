package commands

import "github.com/spf13/cobra"

const (
	appNameLowerCase    = "xipher"
	xipherPubKeyFileExt = ".xpk"
	xipherFileExt       = "." + appNameLowerCase
	envar_XIPHER_SECRET = "XIPHER_SECRET"
)

var secret *string

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

type strFlag struct {
	flagDef
	value string
}

func (f *strFlag) flagFields() (string, string, string, string) {
	return f.name, f.shorthand, f.value, f.usage
}

type boolFlag struct {
	flagDef
	value bool
}

func (f *boolFlag) flagFields() (string, string, bool, string) {
	return f.name, f.shorthand, f.value, f.usage
}

var (

	// Version Flag
	versionFlag = boolFlag{
		flagDef: flagDef{
			name:      "version",
			shorthand: "v",
			usage:     "Shows version info",
		},
	}

	// Public Key File Flag
	publicKeyFileFlag = strFlag{
		flagDef: flagDef{
			name:      "public-key-file",
			shorthand: "p",
			usage:     "Specify path to the public key file",
		},
	}

	// Quantum-safe encryption
	quantumSafeFlag = boolFlag{
		flagDef: flagDef{
			name:      "quantum-safe",
			shorthand: "q",
			usage:     "Uses quantum-safe cryptography",
		},
	}

	// Ignore Password Policy Check Flag
	ignorePasswordCheckFlag = boolFlag{
		flagDef: flagDef{
			name:  "ignore-password-policy",
			usage: "Ignores the password policy check",
		},
	}

	// Auto generate secret key Flag
	autoGenerateSecretKey = boolFlag{
		flagDef: flagDef{
			name:      "auto",
			shorthand: "a",
			usage:     "Auto generate a secret key",
		},
	}

	// Key or Pwd Flag
	keyOrPwdFlag = strFlag{
		flagDef: flagDef{
			name:      "key",
			shorthand: "k",
			usage:     "Specify public key, secret key or a password",
		},
	}

	// Text Flag
	textFlag = strFlag{
		flagDef: flagDef{
			name:      "text",
			shorthand: "t",
			usage:     "Specify the text to encrypt (use '-' to read from stdin)",
		},
	}

	// Ciphertext Flag
	ciphertextFlag = strFlag{
		flagDef: flagDef{
			name:      "ciphertext",
			shorthand: "c",
			usage:     "Specify the ciphertext",
		},
	}

	// File Flag
	fileFlag = strFlag{
		flagDef: flagDef{
			name:      "file",
			shorthand: "f",
			usage:     "Specify file path",
		},
	}

	// Out Flag
	outFlag = strFlag{
		flagDef: flagDef{
			name:      "out",
			shorthand: "o",
			usage:     "Specify an output file path",
		},
	}

	// Compress Flag
	compressFlag = boolFlag{
		flagDef: flagDef{
			name:      "compress",
			shorthand: "c",
			usage:     "Enable compression as the data is encrypted",
		},
	}
)
