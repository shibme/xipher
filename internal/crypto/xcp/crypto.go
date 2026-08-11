package xcp

import (
	"bytes"
	"compress/zlib"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type Writer struct {
	aead         cipher.AEAD
	dst          io.Writer
	buf          bytes.Buffer
	noncePrefix  []byte
	blockCounter uint64
	zWriter      *zlib.Writer
}

// NewEncryptingWriter returns a new io.WriteCloser that encrypts data with the cipher and writes to dst.
func (cipher *SymmetricCipher) NewEncryptingWriter(dst io.Writer, compress bool) (io.WriteCloser, error) {
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, err
	}
	return cipher.newWriter(nonce[:noncePrefixLength], dst, compress)
}

func (cipher *SymmetricCipher) newWriter(noncePrefix []byte, dst io.Writer, compress bool) (*Writer, error) {
	ciphWriter := &Writer{
		aead:        *cipher.aead,
		dst:         dst,
		buf:         bytes.Buffer{},
		noncePrefix: noncePrefix,
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
		return n, fmt.Errorf("encryption failed: %w", err)
	}
	return n, w.flushFull()
}

// flushFull seals and writes every full block currently buffered, but always
// leaves one pending block behind. We can't tell if a block is the last one
// until Close is called, so it must never be flushed early.
func (w *Writer) flushFull() error {
	for w.buf.Len() > ptBlockSize {
		if err := w.sealAndWrite(w.buf.Next(ptBlockSize), false); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) sealAndWrite(block []byte, last bool) error {
	nonce := buildNonce(w.noncePrefix, w.blockCounter, last)
	w.blockCounter++
	ct := w.aead.Seal(nil, nonce, block, nil)
	if _, err := w.dst.Write(ct); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	return nil
}

// Close flushes the last chunk. It does not close the underlying Writer.
func (w *Writer) Close() error {
	if w.zWriter != nil {
		if err := w.zWriter.Close(); err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}
	// Closing zWriter can release more than one block's worth of compressed
	// data at once, so flush any full blocks before sealing the rest as the
	// final block.
	if err := w.flushFull(); err != nil {
		return err
	}
	return w.sealAndWrite(w.buf.Next(ptBlockSize), true)
}

// readFormat identifies which nonce scheme a ciphertext's blocks were sealed
// with. formatUnknown is only ever observed while decoding block 0.
type readFormat int

const (
	formatUnknown readFormat = iota
	// formatFixedNonce is the old scheme: every block reuses the same stored
	// nonce. Kept so ciphertext from older, vulnerable versions can still be read.
	formatFixedNonce
	// formatCounterNonce is the current scheme: prefix + block counter + last-block flag.
	formatCounterNonce
)

type Reader struct {
	aead         cipher.AEAD
	src          io.Reader
	buf          bytes.Buffer
	noncePrefix  []byte
	legacyNonce  []byte
	blockCounter uint64
	format       readFormat
	finished     bool
}

// NewDecryptingReader returns a new io.Reader that decrypts src with the cipher
func (cipher *SymmetricCipher) NewDecryptingReader(src io.Reader) (io.Reader, error) {
	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, err
	}
	return cipher.newReader(nonce, src)
}

func (cipher *SymmetricCipher) newReader(nonce []byte, src io.Reader) (io.Reader, error) {
	ciphReader := &Reader{
		aead:        *cipher.aead,
		src:         src,
		buf:         bytes.Buffer{},
		noncePrefix: nonce[:noncePrefixLength],
		legacyNonce: nonce,
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

// nonceCandidate is one nonce worth trying for the next block. onMatch runs
// when it works: it locks in the format, advances the counter, and reports
// whether this block is the last one.
type nonceCandidate struct {
	nonce   []byte
	onMatch func() (last bool)
}

// candidates lists the nonces worth trying for the next block, in order. A
// short read means we hit the end of the source, so this must be the last
// block. A full-size read is ambiguous: it could be a middle block, or the
// last block if the plaintext happened to end exactly on a block boundary.
//
// Every candidate still has to pass real AEAD authentication, so trying more
// than one doesn't weaken anything. Without the key, an attacker can't make
// a block authenticate under a nonce it wasn't actually sealed with.
func (r *Reader) candidates(shortRead bool) []nonceCandidate {
	switch r.format {
	case formatCounterNonce:
		var cands []nonceCandidate
		if !shortRead {
			cands = append(cands, nonceCandidate{
				nonce:   buildNonce(r.noncePrefix, r.blockCounter, false),
				onMatch: func() bool { r.blockCounter++; return false },
			})
		}
		cands = append(cands, nonceCandidate{
			nonce:   buildNonce(r.noncePrefix, r.blockCounter, true),
			onMatch: func() bool { r.blockCounter++; return true },
		})
		return cands
	case formatFixedNonce:
		return []nonceCandidate{{
			nonce:   r.legacyNonce,
			onMatch: func() bool { return shortRead },
		}}
	default: // formatUnknown: only block 0 is ever decoded without a locked format.
		var cands []nonceCandidate
		if !shortRead {
			cands = append(cands, nonceCandidate{
				nonce: buildNonce(r.noncePrefix, 0, false),
				onMatch: func() bool {
					r.format, r.blockCounter = formatCounterNonce, 1
					return false
				},
			})
		}
		cands = append(cands,
			nonceCandidate{
				nonce: buildNonce(r.noncePrefix, 0, true),
				onMatch: func() bool {
					r.format, r.blockCounter = formatCounterNonce, 1
					return true
				},
			},
			nonceCandidate{
				nonce: r.legacyNonce,
				onMatch: func() bool {
					r.format = formatFixedNonce
					return shortRead
				},
			},
		)
		return cands
	}
}

// readNextBlock reads and decrypts one ciphertext block, returning io.EOF
// once the source is exhausted.
func (r *Reader) readNextBlock() (pt []byte, last bool, err error) {
	var block [ctBlockSize]byte
	n, ioErr := io.ReadFull(r.src, block[:])
	var shortRead bool
	switch ioErr {
	case nil:
	case io.ErrUnexpectedEOF:
		shortRead = true
	case io.EOF:
		return nil, false, io.EOF
	default:
		return nil, false, fmt.Errorf("decryption failed: %w", ioErr)
	}
	ct := block[:n]
	for _, c := range r.candidates(shortRead) {
		if pt, err := r.aead.Open(nil, c.nonce, ct, nil); err == nil {
			return pt, c.onMatch(), nil
		}
	}
	return nil, false, fmt.Errorf("decryption failed: authentication failed")
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.buf.Len() > len(p) {
		return r.buf.Read(p)
	}
	pt, last, err := r.readNextBlock()
	if err == io.EOF {
		// A formatCounterNonce ciphertext always ends with a block flagged as
		// last. Running out of input before we see one means blocks were
		// dropped. The legacy format has no such flag, so for that (and for
		// an empty legacy message with no blocks at all) running out of
		// input just means we're done, same as before this fix.
		if r.format == formatCounterNonce && !r.finished {
			return 0, fmt.Errorf("decryption failed: unexpected end of ciphertext")
		}
		return r.buf.Read(p)
	}
	if err != nil {
		return 0, err
	}
	r.buf.Write(pt)
	if last {
		r.finished = true
		if r.format == formatCounterNonce {
			// Make sure nothing was appended after the block that was sealed as final.
			var extra [1]byte
			if _, err := io.ReadFull(r.src, extra[:]); err != io.EOF {
				return 0, fmt.Errorf("decryption failed: unexpected trailing data")
			}
		}
	}
	return r.buf.Read(p)
}
