package utils

import (
	"encoding/base32"
	"net/url"
	"strings"
)

func encode(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func decode(str string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
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
