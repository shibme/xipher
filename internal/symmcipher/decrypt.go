package symmcipher

import (
	"bytes"
	"compress/zlib"
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Reader struct {
	aead  cipher.AEAD
	src   io.Reader
	buf   bytes.Buffer
	nonce []byte
}

// NewDecryptingReader returns a new io.ReadCloser that decrypts src with the cipher
func (cipher *Cipher) NewDecryptingReader(src io.Reader) (io.ReadCloser, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, err
	}
	return cipher.newReader(nonce, src)
}

func (cipher *Cipher) newReader(nonce []byte, src io.Reader) (io.ReadCloser, error) {
	ciphReader := &Reader{
		aead:  *cipher.aead,
		src:   src,
		buf:   bytes.Buffer{},
		nonce: nonce,
	}
	zReader, err := zlib.NewReader(ciphReader)
	if err != nil {
		return nil, err
	}
	return zReader, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.buf.Len() > len(p) {
		return r.buf.Read(p)
	}
	var block [ctBlockSize]byte
	n, err := io.ReadFull(r.src, block[:])
	if err == nil || err == io.ErrUnexpectedEOF {
		pt, err := r.aead.Open(nil, r.nonce, block[:n], nil)
		if err != nil {
			return 0, err
		}
		r.buf.Write(pt)
		return r.buf.Read(p)
	} else if err == io.EOF {
		return r.buf.Read(p)
	} else {
		return 0, err
	}
}
