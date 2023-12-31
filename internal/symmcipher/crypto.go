package symmcipher

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func (cipher *Cipher) Encrypt(dst io.Writer, src io.Reader, compression bool) error {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if _, err := dst.Write(nonce); err != nil {
		return err
	}
	ciphWriter, err := cipher.newWriter(nonce, dst)
	if err != nil {
		return err
	}
	compressionLevel := zlib.NoCompression
	if compression {
		compressionLevel = zlib.BestCompression
	}
	zWriter, err := zlib.NewWriterLevel(ciphWriter, compressionLevel)
	if err != nil {
		return err
	}
	if _, err = io.Copy(zWriter, src); err != nil {
		return err
	}
	if err = zWriter.Close(); err != nil {
		return err
	}
	return ciphWriter.Close()
}

func (cipher *Cipher) EncryptBytes(data []byte, compression bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = cipher.Encrypt(&buf, bytes.NewReader(data), compression); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Encrypt(dst io.Writer, src io.Reader, key []byte, compression bool) error {
	cipher, err := New(key)
	if err != nil {
		return err
	}
	return cipher.Encrypt(dst, src, compression)
}

func EncryptBytes(data, key []byte, compression bool) (ciphertext []byte, err error) {
	cipher, err := New(key)
	if err != nil {
		return nil, err
	}
	return cipher.EncryptBytes(data, compression)
}

func (cipher *Cipher) Decrypt(dst io.Writer, src io.Reader) error {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return err
	}
	ciphReader, err := cipher.newReader(nonce, src)
	if err != nil {
		return err
	}
	zReader, err := zlib.NewReader(ciphReader)
	if err != nil {
		return err
	}
	if _, err = io.Copy(dst, zReader); err != nil {
		return err
	}
	return zReader.Close()
}

func (cipher *Cipher) DecryptBytes(ciphertext []byte) (data []byte, err error) {
	var buf bytes.Buffer
	if err = cipher.Decrypt(&buf, bytes.NewReader(ciphertext)); err != nil {
		return nil, err
	}
	return buf.Bytes(), err
}

func Decrypt(dst io.Writer, src io.Reader, key []byte) error {
	cipher, err := New(key)
	if err != nil {
		return err
	}
	return cipher.Decrypt(dst, src)
}

func DecryptBytes(ciphertext, key []byte) (data []byte, err error) {
	cipher, err := New(key)
	if err != nil {
		return nil, err
	}
	return cipher.DecryptBytes(ciphertext)
}
