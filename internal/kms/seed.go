package kms

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"
)

// minSeedLength is the minimum length, in raw bytes, of the master seed.
const minSeedLength = 64

// minSeedEntropyBits is the minimum acceptable Shannon entropy (in bits per
// byte) of the master seed. For a short sample (~64 bytes) the measurable
// entropy of true random data is bounded by log2(len) and sits around 5.5-5.9
// bits/byte, so this threshold rejects structured / repeated input (entropy
// near 0) while accepting genuine random seeds.
const minSeedEntropyBits = 4.5

// loadSeed reads the seed file, decodes it if it is hex/base64 encoded,
// validates length and entropy, deletes the file, and returns the raw bytes.
//
// The file is deleted only after successful validation so a misconfigured
// deploy can be corrected without regenerating the seed.
func loadSeed(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading seed file %q: %w", path, err)
	}

	seed := decodeSeed(raw)

	if len(seed) < minSeedLength {
		return nil, fmt.Errorf("seed too short: need at least %d bytes, got %d", minSeedLength, len(seed))
	}
	if e := shannonEntropy(seed); e < minSeedEntropyBits {
		return nil, fmt.Errorf("seed entropy too low: %.2f bits/byte (need >= %.1f); seed must be high-entropy random data", e, minSeedEntropyBits)
	}

	// Delete the file so the seed does not persist on disk after startup.
	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("clearing seed file %q: %w", path, err)
	}
	return seed, nil
}

// decodeSeed extrapolates the raw seed bytes. If the trimmed content is valid
// hex or base64, it is decoded; otherwise the bytes are used verbatim.
func decodeSeed(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return raw
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) >= minSeedLength {
		return b
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) >= minSeedLength {
		return b
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) >= minSeedLength {
		return b
	}
	return raw
}

// shannonEntropy returns the Shannon entropy of data in bits per byte.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
