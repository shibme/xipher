package main

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"syscall/js"

	"dev.shib.me/xipher/utils"
)

const (
	ctMinLegthRequired = 128 * 1024 // Arbitrary value based on max key length with generously possible header length
	readableBlockSize  = 32 * 1024
)

func decryptStr(args []js.Value) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("supported arguments: secret key or password (required), ciphertext (required)")
	}
	secretKeyOrPwd := args[0].String()
	ciphertext := args[1].String()
	message, err := utils.DecryptData(secretKeyOrPwd, ciphertext)
	if err != nil {
		return nil, err
	}
	return string(message), nil
}

var (
	decrypters   = make(map[int]*decrypter)
	decryptersMu sync.Mutex
	decrypterId  int = 1
)

type decrypter struct {
	keyOrPwd string
	reader   io.Reader
	src      *bytes.Buffer
}

func (d *decrypter) initReaderGracefully() (err error) {
	if d.reader == nil {
		d.reader, err = utils.DecryptingReader(d.keyOrPwd, d.src)
	}
	return
}

func (d *decrypter) transform(data []byte) ([]byte, error) {
	if _, err := d.src.Write(data); err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	if d.src.Len() >= ctMinLegthRequired {
		if err := d.initReaderGracefully(); err != nil {
			return nil, err
		}
		block := make([]byte, readableBlockSize)
		for d.src.Len() >= ctMinLegthRequired {
			n, err := d.reader.Read(block)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				break
			}
			buf.Write(block[:])
		}
	}
	return buf.Bytes(), nil
}

func (d *decrypter) close() ([]byte, error) {
	if err := d.initReaderGracefully(); err != nil {
		return nil, err
	}
	return io.ReadAll(d.reader)
}

func newDecryptingTransformer(args []js.Value) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("supported arguments: secret key or password (required)")
	}
	decryptersMu.Lock()
	defer decryptersMu.Unlock()
	keyOrPwd := args[0].String()
	dec := &decrypter{
		keyOrPwd: keyOrPwd,
		src:      new(bytes.Buffer),
	}
	id := decrypterId
	decrypters[id] = dec
	decrypterId++
	return id, nil
}

func decryptThroughTransformer(args []js.Value) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("supported arguments: id (required), input (required)")
	}
	decryptersMu.Lock()
	id := args[0].Int()
	inputJSArray := args[1]
	dec, ok := decrypters[id]
	decryptersMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("decrypter not found for id: %d", id)
	}
	inputLength := inputJSArray.Get("length").Int()
	inputData := make([]byte, inputLength)
	js.CopyBytesToGo(inputData, inputJSArray)
	outputData, err := dec.transform(inputData)
	if err != nil {
		return nil, err
	}
	outputJSArray := js.Global().Get("Uint8Array").New(len(outputData))
	js.CopyBytesToJS(outputJSArray, outputData)
	return outputJSArray, nil
}

func closeDecryptingTransformer(args []js.Value) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("supported arguments: id (required)")
	}
	decryptersMu.Lock()
	id := args[0].Int()
	dec, ok := decrypters[id]
	if !ok {
		decryptersMu.Unlock()
		return nil, fmt.Errorf("decrypter not found for id: %d", id)
	}
	delete(decrypters, id)
	decryptersMu.Unlock()
	outputData, err := dec.close()
	if err != nil {
		return nil, err
	}
	outputJSArray := js.Global().Get("Uint8Array").New(len(outputData))
	js.CopyBytesToJS(outputJSArray, outputData)
	return outputJSArray, nil
}
