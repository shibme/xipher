package commands

import (
	"bytes"
	"fmt"
	"strings"
	"syscall"
	"unicode"

	"golang.org/x/term"
)

const (
	pwdSpecialChars = "!@#$%^&*()_+="
	pwdLength       = 10
)

var errInvalidPassword = fmt.Errorf("xipher: please set a decent password with at least %d characters, including at least one uppercase letter, one lowercase letter, one number, and one of the following special characters: %s", pwdLength, pwdSpecialChars)

func pwdCheck(password string) error {
	var (
		upp, low, num, sym bool
		tot                uint32
	)
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			upp = true
			tot++
		case unicode.IsLower(char):
			low = true
			tot++
		case unicode.IsNumber(char):
			num = true
			tot++
		case strings.ContainsRune(pwdSpecialChars, char):
			sym = true
			tot++
		default:
			return errInvalidPassword
		}
	}
	if !(upp && low && num && sym && tot >= pwdLength) {
		return errInvalidPassword
	}
	return nil
}

func getHiddenInputFromUser(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	input, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return input, err
}

func getPasswordFromUser(confirm, ignorePolicyCheck bool) ([]byte, error) {
	password, err := getHiddenInputFromUser("Enter a Password: ")
	if err != nil {
		return nil, err
	}
	if !ignorePolicyCheck {
		if err = pwdCheck(string(password)); err != nil {
			return nil, err
		}
	}
	if confirm {
		if confirmPassword, err := getHiddenInputFromUser("Confirm Password: "); err != nil {
			return nil, err
		} else if !bytes.Equal(password, confirmPassword) {
			return nil, fmt.Errorf("passwords do not match")
		}
	}
	return password, nil
}
