package symmcipher

import (
	"bytes"
	"compress/zlib"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Writer struct {
	aead    cipher.AEAD
	dst     io.Writer
	buf     bytes.Buffer
	nonce   []byte
	zWriter *zlib.Writer
}

// NewEncryptingWriter returns a new io.WriteCloser that encrypts data with the cipher and writes to dst.
func (cipher *Cipher) NewEncryptingWriter(dst io.Writer, compression bool) (io.WriteCloser, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, err
	}
	return cipher.newWriter(nonce, dst, compression)
}

func (cipher *Cipher) newWriter(nonce []byte, dst io.Writer, compression bool) (*Writer, error) {
	ciphWriter := &Writer{
		aead:  *cipher.aead,
		dst:   dst,
		buf:   bytes.Buffer{},
		nonce: nonce,
	}
	compressionLevel := zlib.NoCompression
	if compression {
		compressionLevel = zlib.BestCompression
	}
	zWriter, err := zlib.NewWriterLevel(&ciphWriter.buf, compressionLevel)
	if err != nil {
		return nil, err
	}
	ciphWriter.zWriter = zWriter
	return ciphWriter, nil
}

func (w *Writer) Write(p []byte) (n int, err error) {
	n, _ = w.zWriter.Write(p)
	return n, w.flush(ptBlockSize)
}

func (w *Writer) flush(minBufSize int) error {
	for w.buf.Len() >= minBufSize {
		block := w.buf.Next(ptBlockSize)
		ct := w.aead.Seal(nil, w.nonce, block, nil)
		if _, err := w.dst.Write(ct); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes the last chunk. It does not close the underlying Writer.
func (w *Writer) Close() error {
	if err := w.zWriter.Close(); err != nil {
		return err
	}
	return w.flush(1)
}
