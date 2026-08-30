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
	nonce        []byte
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
		return n, fmt.Errorf("encryption failed: %w", err)
	}
	return n, w.flushFull()
}

// flushFull seals and writes every full block currently buffered, but always
// leaves one pending block behind. We can't tell if a block is the last one
// until Close is called, so it must never be flushed early. Reaching this loop
// at all means the message spans more than one block.
func (w *Writer) flushFull() error {
	for w.buf.Len() > ptBlockSize {
		nonce := buildNonce(w.nonce[:noncePrefixLength], w.blockCounter, false)
		if err := w.sealAndWrite(nonce, w.buf.Next(ptBlockSize)); err != nil {
			return err
		}
		w.blockCounter++
	}
	return nil
}

func (w *Writer) sealAndWrite(nonce, block []byte) error {
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
	block := w.buf.Next(ptBlockSize)
	// A message that fits in a single partial block is sealed with the stored
	// nonce exactly as it sits on the wire, which is byte for byte what every
	// version of this format has produced for such a message. That keeps data
	// under one block readable by older releases, and there was never a
	// nonce-reuse problem here: a single block means a single Seal call.
	//
	// Per-block framing isn't needed in this case either. There is no trailing
	// block to drop, and shaving bytes off the only block fails authentication.
	// Anything longer uses the per-block counter nonce, where a dropped or
	// reordered block does need to be detectable.
	nonce := w.nonce
	if w.blockCounter > 0 || len(block) == ptBlockSize {
		nonce = buildNonce(w.nonce[:noncePrefixLength], w.blockCounter, true)
	}
	return w.sealAndWrite(nonce, block)
}

// readFormat identifies which nonce scheme a ciphertext's blocks were sealed
// with. formatUnknown is only ever observed while decoding block 0.
type readFormat int

const (
	formatUnknown readFormat = iota
	// formatStoredNonce means blocks are sealed with the stored nonce as-is. A
	// single-block message is written this way on purpose, so it stays readable
	// by older releases. Messages from before the nonce-reuse fix also land
	// here, and those reused that one nonce across every block.
	formatStoredNonce
	// formatCounterNonce is the multi-block scheme: prefix + block counter + last-block flag.
	formatCounterNonce
)

type Reader struct {
	aead         cipher.AEAD
	src          io.Reader
	buf          bytes.Buffer
	noncePrefix  []byte
	storedNonce  []byte
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
		storedNonce: nonce,
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
	case formatStoredNonce:
		return []nonceCandidate{{
			nonce:   r.storedNonce,
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
				nonce: r.storedNonce,
				onMatch: func() bool {
					r.format = formatStoredNonce
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
		// dropped. formatStoredNonce carries no such flag, so there (and for
		// a pre-fix empty message with no blocks at all) running out of input
		// just means we're done.
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
