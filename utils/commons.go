package utils

import (
	"bytes"
	"encoding/base32"
	"io"
	"net/url"
	"strings"
)

func encode(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func encodingWriter(dst io.Writer) io.WriteCloser {
	return base32.NewEncoder(base32.StdEncoding.WithPadding(base32.NoPadding), dst)
}

func decode(str string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
}

func decodingReader(src io.Reader) io.Reader {
	return base32.NewDecoder(base32.StdEncoding.WithPadding(base32.NoPadding), src)
}

func getSanitisedValue(strOrUrl string, patternVerifier func(string) bool) string {
	if u, err := url.Parse(strOrUrl); err == nil {
		for _, values := range u.Query() {
			for _, value := range values {
				trimmedValue := strings.TrimSpace(value)
				if patternVerifier(trimmedValue) {
					return trimmedValue
				}
			}
		}
	}
	return strings.TrimSpace(strOrUrl)
}

type peekableReader struct {
	r   io.Reader
	buf bytes.Buffer
}

func (pr *peekableReader) fillBuffer(n int) (err error) {
	if pr.buf.Len() >= n {
		return nil
	}
	p := make([]byte, n-pr.buf.Len())
	n, err = pr.r.Read(p)
	if n > 0 {
		pr.buf.Write(p[:n])
	}
	return
}

func (pr *peekableReader) Peek(n int) ([]byte, error) {
	err := pr.fillBuffer(n)
	if err != nil {
		return nil, err
	}
	return pr.buf.Bytes()[:n], nil
}

func (pr *peekableReader) Discard(n int) (int, error) {
	err := pr.fillBuffer(n)
	if err != nil {
		return 0, err
	}
	return pr.buf.Read(make([]byte, n))
}

func (pr *peekableReader) Read(p []byte) (n int, err error) {
	err = pr.fillBuffer(len(p))
	if err == nil || err == io.EOF {
		n, err = pr.buf.Read(p)
	} else {
		n = 0
	}
	return
}
