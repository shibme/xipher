//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"

	"xipher.org/xipher"
	"xipher.org/xipher/internal/utils"
)

func newSecretKey(args []js.Value) (any, error) {
	if len(args) > 0 {
		return nil, fmt.Errorf("no arguments required for new secret key generation")
	}
	sk, err := xipher.NewSecretKey()
	if err != nil {
		return nil, err
	}
	return sk.String()
}

func secretKeyFromSeed(args []js.Value) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("supported arguments: seed (required)")
	}
	seedJSArray := args[0]
	seedLength := seedJSArray.Get("length").Int()
	if seedLength != 64 {
		return nil, fmt.Errorf("seed must be exactly 64 bytes, got %d", seedLength)
	}
	seedBytes := make([]byte, 64)
	js.CopyBytesToGo(seedBytes, seedJSArray)
	sk, err := xipher.SecretKeyFromSeed([64]byte(seedBytes))
	if err != nil {
		return nil, err
	}
	return sk.String()
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
	pkStr, _, err := utils.GetPublicKey(secret, quantumSafe)
	if err != nil {
		return nil, err
	}
	return pkStr, nil
}
