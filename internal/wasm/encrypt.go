package main

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"syscall/js"

	"dev.shib.me/xipher/utils"
)

func encryptStr(args []js.Value) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("supported arguments: public key, secret key or password (required), message (required)")
	}
	keyOrPwd := args[0].String()
	message := args[1].String()
	ciphertext, err := utils.EncryptData(keyOrPwd, []byte(message), true)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

var (
	encrypters   = make(map[int]*encrypter)
	encryptersMu sync.Mutex
	encrypterId  int = 1
)

type encrypter struct {
	writer io.WriteCloser
	dst    *bytes.Buffer
}

func (e *encrypter) write(data []byte) ([]byte, error) {
	_, err := e.writer.Write(data)
	if err != nil {
		return nil, err
	}
	if e.dst.Len() > 0 {
		return e.dst.Next(e.dst.Len()), nil
	}
	return nil, nil
}

func (e *encrypter) close() ([]byte, error) {
	err := e.writer.Close()
	if err != nil {
		return nil, err
	}
	return e.dst.Next(e.dst.Len()), nil
}

func newStreamEncrypter(args []js.Value) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("supported arguments: public key, secret key or password (required), compress (required)")
	}
	encryptersMu.Lock()
	defer encryptersMu.Unlock()
	keyOrPwd := args[0].String()
	compress := args[1].Bool()
	enc := &encrypter{
		dst: new(bytes.Buffer),
	}
	writer, err := utils.EncryptingWriter(keyOrPwd, enc.dst, compress)
	if err != nil {
		return nil, err
	}
	enc.writer = writer
	id := encrypterId
	encrypters[id] = enc
	encrypterId++
	return id, nil
}

func writeToEncrypter(args []js.Value) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("supported arguments: id (required), input (required)")
	}
	encryptersMu.Lock()
	id := args[0].Int()
	inputJSArray := args[1]
	enc, ok := encrypters[id]
	encryptersMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("encrypter not found for id: %d", id)
	}
	inputLength := inputJSArray.Get("length").Int()
	inputData := make([]byte, inputLength)
	js.CopyBytesToGo(inputData, inputJSArray)
	outputData, err := enc.write(inputData)
	if err != nil {
		return nil, err
	}
	outputJSArray := js.Global().Get("Uint8Array").New(len(outputData))
	js.CopyBytesToJS(outputJSArray, outputData)
	return outputJSArray, nil
}

func closeEncrypter(args []js.Value) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("supported arguments: id (required)")
	}
	encryptersMu.Lock()
	id := args[0].Int()
	enc, ok := encrypters[id]
	if !ok {
		encryptersMu.Unlock()
		return nil, fmt.Errorf("encrypter not found for id: %d", id)
	}
	delete(encrypters, id)
	encryptersMu.Unlock()
	outputData, err := enc.close()
	if err != nil {
		return nil, err
	}
	outputJSArray := js.Global().Get("Uint8Array").New(len(outputData))
	js.CopyBytesToJS(outputJSArray, outputData)
	return outputJSArray, nil
}
