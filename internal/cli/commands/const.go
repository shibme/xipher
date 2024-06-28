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

var (

	// Version Flag
	versionFlag = flagDef{
		name:      "version",
		shorthand: "v",
		usage:     "Shows version info",
	}

	// Public Key File Flag
	publicKeyFileFlag = flagDef{
		name:      "public-key-file",
		shorthand: "p",
		usage:     "Specify path to the public key file",
	}

	// Quantum-safe encryption
	quantumSafeFlag = flagDef{
		name:      "quantum-safe",
		shorthand: "q",
		usage:     "Uses quantum-safe cryptography",
	}

	// Ignore Password Policy Check Flag
	ignorePasswordCheckFlag = flagDef{
		name:  "ignore-password-policy",
		usage: "Ignores the password policy check",
	}

	// Auto generate secret key Flag
	autoGenerateSecretKey = flagDef{
		name:      "auto",
		shorthand: "a",
		usage:     "Auto generate a secret key",
	}

	// Key or Pwd Flag
	keyOrPwdFlag = flagDef{
		name:      "key",
		shorthand: "k",
		usage:     "Specify public key, secret key or a password",
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
