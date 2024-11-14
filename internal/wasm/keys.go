package main

import (
	"fmt"
	"syscall/js"

	"dev.shib.me/xipher/utils"
)

func newSecretKey(args []js.Value) (any, error) {
	if len(args) > 0 {
		return nil, fmt.Errorf("no arguments required for new secret key generation")
	}
	sk, err := utils.NewSecretKey()
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func getPublicKey(args []js.Value) (any, error) {
	if len(args) != 1 && len(args) != 2 {
		return nil, fmt.Errorf("supported arguments: secret key (required), quantum safe (optional)")
	}
	secret := args[0].String()
	quantumSafe := false
	if len(args) == 2 {
		quantumSafe = args[1].Bool()
	}
	pk, err := utils.GetPublicKey(secret, quantumSafe)
	if err != nil {
		return nil, err
	}
	return pk, nil
}
