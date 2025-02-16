package xipher

import (
	"bytes"
	"encoding/base32"
	"io"
)

func encode(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func encoder(dst io.Writer) io.WriteCloser {
	return base32.NewEncoder(base32.StdEncoding.WithPadding(base32.NoPadding), dst)
}

func decode(str string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
}

func decoder(src io.Reader) io.Reader {
	return base32.NewDecoder(base32.StdEncoding.WithPadding(base32.NoPadding), src)
}

type dualWriteCloser struct {
	primary   io.WriteCloser
	secondary io.WriteCloser
}

func (dwc *dualWriteCloser) Write(p []byte) (n int, err error) {
	return dwc.primary.Write(p)
}

func (dwc *dualWriteCloser) Close() error {
	if err := dwc.primary.Close(); err != nil {
		return err
	}
	return dwc.secondary.Close()
}

type peekableReader struct {
	r   io.Reader
	buf bytes.Buffer
}

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

func (pr *peekableReader) Peek(n int) ([]byte, error) {
	if err := pr.fill(n); err != nil {
		return nil, err
	}
	return pr.buf.Bytes()[:n], nil
}

func (pr *peekableReader) Read(p []byte) (n int, err error) {
	if err = pr.fill(len(p)); err == nil || err == io.EOF || err == io.ErrUnexpectedEOF {
		n, err = pr.buf.Read(p)
	} else {
		n = 0
	}
	return
}

func (pr *peekableReader) Discard(n int) (int, error) {
	return pr.Read(make([]byte, n))
}
