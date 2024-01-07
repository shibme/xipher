package symcipher

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
func (cipher *SymmetricCipher) NewEncryptingWriter(dst io.Writer, compress bool) (io.WriteCloser, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, err
	}
	return cipher.newWriter(nonce, dst, compress)
}

func (cipher *SymmetricCipher) newWriter(nonce []byte, dst io.Writer, compress bool) (*Writer, error) {
	ciphWriter := &Writer{
		aead:  *cipher.aead,
		dst:   dst,
		buf:   bytes.Buffer{},
		nonce: nonce,
	}
	if compress {
		if _, err := dst.Write([]byte{1}); err != nil {
			return nil, err
		}
		zWriter, err := zlib.NewWriterLevel(&ciphWriter.buf, zlib.BestCompression)
		if err != nil {
			return nil, err
		}
		ciphWriter.zWriter = zWriter
	} else {
		if _, err := dst.Write([]byte{0}); err != nil {
			return nil, err
		}
	}
	return ciphWriter, nil
}

func (w *Writer) Write(p []byte) (n int, err error) {
	if w.zWriter == nil {
		n, err = w.buf.Write(p)
	} else {
		n, err = w.zWriter.Write(p)
	}
	if err != nil {
		return n, err
	}
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
	if w.zWriter != nil {
		if err := w.zWriter.Close(); err != nil {
			return err
		}
	}
	return w.flush(1)
}

type Reader struct {
	aead  cipher.AEAD
	src   io.Reader
	buf   bytes.Buffer
	nonce []byte
}

// NewDecryptingReader returns a new io.ReadCloser that decrypts src with the cipher
func (cipher *SymmetricCipher) NewDecryptingReader(src io.Reader) (io.ReadCloser, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, err
	}
	return cipher.newReader(nonce, src)
}

func (cipher *SymmetricCipher) newReader(nonce []byte, src io.Reader) (io.ReadCloser, error) {
	ciphReader := &Reader{
		aead:  *cipher.aead,
		src:   src,
		buf:   bytes.Buffer{},
		nonce: nonce,
	}
	compressFlag := make([]byte, 1)
	if _, err := io.ReadFull(src, compressFlag); err != nil {
		return nil, err
	}
	if compressFlag[0] == 0 {
		return io.NopCloser(ciphReader), nil
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
