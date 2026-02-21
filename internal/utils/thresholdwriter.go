package utils

import (
	"fmt"
	"os"
)

// ThresholdFileWriter buffers writes until a threshold length is reached,
// then creates the output file, flushes the buffer, and passes all subsequent writes through.
type ThresholdFileWriter struct {
	filePath  string
	file      *os.File
	buf       []byte
	threshold int
	flushed   bool
	discarded bool
}

func NewThresholdFileWriter(filePath string, threshold int) *ThresholdFileWriter {
	return &ThresholdFileWriter{
		filePath:  filePath,
		buf:       make([]byte, 0, threshold),
		threshold: threshold,
	}
}

func (tw *ThresholdFileWriter) openFile() error {
	f, err := os.Create(tw.filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", tw.filePath, err)
	}
	tw.file = f
	return nil
}

func (tw *ThresholdFileWriter) Write(p []byte) (int, error) {
	if tw.discarded {
		return 0, fmt.Errorf("writer has been discarded")
	}

	if tw.flushed {
		return tw.file.Write(p)
	}

	tw.buf = append(tw.buf, p...)

	if len(tw.buf) >= tw.threshold {
		if err := tw.openFile(); err != nil {
			return 0, err
		}
		tw.flushed = true
		_, err := tw.file.Write(tw.buf)
		tw.buf = nil
		if err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// Flush writes any remaining buffered data, creating the file if needed, and syncs it.
func (tw *ThresholdFileWriter) Flush() error {
	if tw.discarded {
		return fmt.Errorf("writer has been discarded")
	}
	if !tw.flushed && len(tw.buf) > 0 {
		if err := tw.openFile(); err != nil {
			return err
		}
		tw.flushed = true
		_, err := tw.file.Write(tw.buf)
		tw.buf = nil
		if err != nil {
			return err
		}
	}
	if tw.file != nil {
		return tw.file.Sync()
	}
	return nil
}

// Discard drops the buffer without writing and removes the file if it was already created.
func (tw *ThresholdFileWriter) Discard() error {
	tw.discarded = true
	tw.buf = nil
	if tw.file != nil {
		tw.file.Close()
		tw.file = nil
		return os.Remove(tw.filePath)
	}
	return nil
}

// Close flushes remaining data and closes the file.
func (tw *ThresholdFileWriter) Close() error {
	if tw.discarded {
		return nil
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if tw.file != nil {
		return tw.file.Close()
	}
	return nil
}
