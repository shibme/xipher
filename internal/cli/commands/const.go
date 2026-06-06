package commands

import (
	"github.com/spf13/cobra"
	"xipher.org/xipher"
)

const (
	xipherPubKeyFileExt = ".xpk"
	envar_XIPHER_SECRET = "XIPHER_SECRET"
	fileWriteThreshold  = 1024 * 1024
)

var (
	secret        *string
	xipherFileExt = "." + xipher.Info.AppNameLC
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

	// Encrypt Stream Command
	encryptStreamCmd *cobra.Command

	// Decrypt Command
	decryptCmd *cobra.Command

	// Decrypt String Command
	decryptTxtCmd *cobra.Command

	// Decrypt Stream Command
	decryptStreamCmd *cobra.Command

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

func (f *strFlag) fields() (string, string, string, string) {
	return f.name, f.shorthand, f.value, f.usage
}

type boolFlag struct {
	flagDef
	value bool
}

func (f *boolFlag) fields() (string, string, bool, string) {
	return f.name, f.shorthand, f.value, f.usage
}

var (

	// Version Flag
	versionFlag = boolFlag{
		flagDef: flagDef{
			name:      "version",
			shorthand: "v",
			usage:     "Show version info",
		},
	}

	// Public Key File Flag
	publicKeyFileFlag = strFlag{
		flagDef: flagDef{
			name:      "public-key-file",
			shorthand: "p",
			usage:     "Path to write the public key file",
		},
	}

	// Quantum-safe encryption
	quantumSafeFlag = boolFlag{
		flagDef: flagDef{
			name:      "quantum-safe",
			shorthand: "q",
			usage:     "Use quantum-safe hybrid cryptography (X25519 + ML-KEM-1024)",
		},
	}

	// Ignore Password Policy Check Flag
	ignorePasswordCheckFlag = boolFlag{
		flagDef: flagDef{
			name:  "ignore-password-policy",
			usage: "Skip the password policy check",
		},
	}

	// Auto generate secret key Flag
	autoGenerateSecretKey = boolFlag{
		flagDef: flagDef{
			name:      "auto",
			shorthand: "a",
			usage:     "Auto-generate a secret key",
		},
	}

	// Key or Pwd Flag
	keyOrPwdFlag = strFlag{
		flagDef: flagDef{
			name:      "key",
			shorthand: "k",
			usage:     "Public key, secret key, password, or a URL/domain serving a public key",
		},
	}

	// Fetch Flag: treat the key value as a URL/domain and fetch the public key from it
	fetchKeyFlag = boolFlag{
		flagDef: flagDef{
			name:  "fetch",
			usage: "Fetch the public key by treating the key value as a URL or domain",
		},
	}

	// Text Flag
	textFlag = strFlag{
		flagDef: flagDef{
			name:      "text",
			shorthand: "t",
			usage:     "Text to encrypt (use '-' to read from stdin)",
		},
	}

	// Ciphertext Flag
	ciphertextFlag = strFlag{
		flagDef: flagDef{
			name:      "ciphertext",
			shorthand: "c",
			usage:     "Ciphertext to decrypt",
		},
	}

	// Source File Flag
	sourceFileFlag = strFlag{
		flagDef: flagDef{
			name:      "file",
			shorthand: "f",
			usage:     "Path to the input file",
		},
	}

	// Output File Flag
	outputFileFlag = strFlag{
		flagDef: flagDef{
			name:      "out",
			shorthand: "o",
			usage:     "Path to the output file",
		},
	}

	// Compress Flag
	compressFlag = boolFlag{
		flagDef: flagDef{
			name:      "compress",
			shorthand: "c",
			usage:     "Compress data before encryption",
		},
	}

	// Format Flag
	jsonFlag = boolFlag{
		flagDef: flagDef{
			name:      "json",
			shorthand: "j",
			usage:     "Output in JSON format",
		},
	}

	// Force Flag
	overwriteFlag = boolFlag{
		flagDef: flagDef{
			name:  "overwrite",
			usage: "Overwrite the file if it exists",
		},
	}

	// To Xipher text Flag
	toXipherTxtFlag = boolFlag{
		flagDef: flagDef{
			name:  "xiphertext",
			usage: "Encode output as xipher text",
		},
	}
)
