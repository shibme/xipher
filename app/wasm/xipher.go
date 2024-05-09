package main

import (
	"fmt"
	"syscall/js"

	"dev.shib.me/xipher/app/internal/utils"
)

func newSecretKey() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			return "Invalid no of arguments passed"
		}
		sk, err := utils.KeyGen()
		if err != nil {
			fmt.Printf(err.Error())
			return err.Error()
		}
		return sk
	})
	return jsonFunc
}

func pubKeyFromPrivKey() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		sk := args[0].String()
		quantumSafe := args[1].Bool()
		pk, err := utils.PubKeyForPrivKey(sk, quantumSafe)
		if err != nil {
			fmt.Printf(err.Error())
			return err.Error()
		}
		return pk
	})
	return jsonFunc
}

func pubKeyFromPassword() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		password := args[0].String()
		quantumSafe := args[1].Bool()
		pk, err := utils.PubKeyForPassword([]byte(password), quantumSafe)
		if err != nil {
			fmt.Printf(err.Error())
			return err.Error()
		}
		return pk
	})
	return jsonFunc
}

func encryptStr() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		pk := args[0].String()
		message := args[1].String()
		ciphertext, err := utils.EncryptText(pk, message)
		if err != nil {
			fmt.Printf(err.Error())
			return err.Error()
		}
		return ciphertext
	})
	return jsonFunc

}

func decryptStrWithSecretKey() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		privKey := args[0].String()
		ciphertext := args[1].String()
		message, err := utils.DecryptTextWithSecretKeyStr(privKey, ciphertext)
		if err != nil {
			fmt.Printf(err.Error())
			return err.Error()
		}
		return message
	})
	return jsonFunc
}

func decryptStrWithPassword() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		password := args[0].String()
		ciphertext := args[1].String()
		message, err := utils.DecryptTextWithPassword(password, ciphertext)
		if err != nil {
			fmt.Printf(err.Error())
			return err.Error()
		}
		return message
	})
	return jsonFunc
}
