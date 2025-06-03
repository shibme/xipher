package xipher

import (
	"bytes"
	"encoding/base32"
	"io"
)

// encode encodes the given byte slice using base32 encoding without padding.
// This is used for encoding keys and ciphertext into human-readable strings.
func encode(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// encoder returns a WriteCloser that writes base32-encoded data to dst.
// The encoder uses standard base32 encoding without padding.
func encoder(dst io.Writer) io.WriteCloser {
	return base32.NewEncoder(base32.StdEncoding.WithPadding(base32.NoPadding), dst)
}

// decode decodes a base32-encoded string into bytes.
// This is used for decoding keys and ciphertext from string format.
func decode(str string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
}

// decoder returns a Reader that reads base32-decoded data from src.
// The decoder uses standard base32 encoding without padding.
func decoder(src io.Reader) io.Reader {
	return base32.NewDecoder(base32.StdEncoding.WithPadding(base32.NoPadding), src)
}

// dualWriteCloser is a WriteCloser that manages two separate WriteClosers.
// It writes to the primary writer and ensures both writers are closed properly.
// This is used when encryption and encoding need to be chained together.
type dualWriteCloser struct {
	primary   io.WriteCloser // The primary writer (e.g., encryption writer)
	secondary io.WriteCloser // The secondary writer (e.g., encoding writer)
}

// Write writes data to the primary WriteCloser.
// The secondary WriteCloser is managed separately during Close().
func (dwc *dualWriteCloser) Write(p []byte) (n int, err error) {
	return dwc.primary.Write(p)
}

// Close closes both the primary and secondary WriteClosers.
// It closes the primary first, then the secondary, returning any error encountered.
func (dwc *dualWriteCloser) Close() error {
	if err := dwc.primary.Close(); err != nil {
		return err
	}
	return dwc.secondary.Close()
}

// peekableReader is a Reader that allows peeking at upcoming data without consuming it.
// It maintains an internal buffer to support look-ahead operations needed for
// detecting ciphertext prefixes and other format markers.
type peekableReader struct {
	r   io.Reader    // The underlying reader
	buf bytes.Buffer // Internal buffer for peeked data
}

// fill ensures the internal buffer contains at least n bytes by reading from the underlying reader.
// It returns an error if the underlying reader fails or reaches EOF before n bytes are available.
func (pr *peekableReader) fill(n int) (err error) {
	for pr.buf.Len() < n && err == nil {
		p := make([]byte, n-pr.buf.Len())
		n, err = pr.r.Read(p)
		if _, e := pr.buf.Write(p[:n]); e != nil {
			err = e
		}
	}
	return
}

// Peek returns the next n bytes without advancing the reader.
// The returned bytes remain valid until the next call to Read or Peek.
func (pr *peekableReader) Peek(n int) ([]byte, error) {
	if err := pr.fill(n); err != nil {
		return nil, err
	}
	return pr.buf.Bytes()[:n], nil
}

// Read reads data from the buffered reader, implementing the io.Reader interface.
// It first tries to satisfy the read from the internal buffer, then from the underlying reader.
func (pr *peekableReader) Read(p []byte) (n int, err error) {
	if err = pr.fill(len(p)); err == nil || err == io.EOF || err == io.ErrUnexpectedEOF {
		n, err = pr.buf.Read(p)
	} else {
		n = 0
	}
	return
}

// Discard skips the next n bytes from the reader.
// This is equivalent to reading n bytes and discarding the result.
func (pr *peekableReader) Discard(n int) (int, error) {
	return pr.Read(make([]byte, n))
}
