package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"dev.shib.me/xipher/app/internal/utils"
)

type jsr struct {
	Result any    `json:"result,omitempty"`
	Err    string `json:"error,omitempty"`
}

func jsReturn(result any, err error) string {
	r := jsr{Result: result}
	if err != nil {
		r.Err = err.Error()
	}
	jsonReturn, errJson := json.Marshal(r)
	if errJson != nil {
		return fmt.Sprintf(`{"error":"%s"}`, errJson.Error())
	}
	return string(jsonReturn)
}

func newSecretKey() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			return jsReturn("", fmt.Errorf("Invalid no of arguments passed"))
		}
		sk, err := utils.NewSecretKey()
		if err != nil {
			return jsReturn("", err)
		}
		return jsReturn(sk, nil)
	})
	return jsonFunc
}

func getPublicKey() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return jsReturn("", fmt.Errorf("Invalid no of arguments passed"))
		}
		secret := args[0].String()
		quantumSafe := args[1].Bool()
		pk, err := utils.GetPublicKey(secret, quantumSafe)
		if err != nil {
			return jsReturn("", err)
		}
		return jsReturn(pk, nil)
	})
	return jsonFunc
}

func encryptStr() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return jsReturn("", fmt.Errorf("Invalid no of arguments passed"))
		}
		pk := args[0].String()
		message := args[1].String()
		ciphertext, err := utils.EncryptDataWithPubKeyStr(pk, []byte(message))
		if err != nil {
			return jsReturn("", err)
		}
		return jsReturn(ciphertext, nil)
	})
	return jsonFunc

}

func decryptStr() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return jsReturn("", fmt.Errorf("Invalid no of arguments passed"))
		}
		secret := args[0].String()
		ciphertext := args[1].String()
		message, err := utils.DecryptText(secret, ciphertext)
		if err != nil {
			return jsReturn("", err)
		}
		return jsReturn(message, nil)
	})
	return jsonFunc
}
