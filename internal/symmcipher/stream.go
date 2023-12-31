package symmcipher

import (
	"bytes"
	"crypto/cipher"
	"io"
)

type Reader struct {
	aead  cipher.AEAD
	src   io.Reader
	buf   bytes.Buffer
	nonce []byte
}

func (cipher *Cipher) newReader(nonce []byte, src io.Reader) (*Reader, error) {
	var buf bytes.Buffer
	return &Reader{
		aead:  *cipher.aead,
		src:   src,
		buf:   buf,
		nonce: nonce,
	}, nil
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

type Writer struct {
	aead  cipher.AEAD
	dst   io.Writer
	buf   bytes.Buffer
	nonce []byte
}

func (cipher *Cipher) newWriter(nonce []byte, dst io.Writer) (*Writer, error) {
	return &Writer{
		aead:  *cipher.aead,
		dst:   dst,
		buf:   bytes.Buffer{},
		nonce: nonce,
	}, nil
}

func (w *Writer) Write(p []byte) (n int, err error) {
	n, _ = w.buf.Write(p)
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
	return w.flush(1)
}
