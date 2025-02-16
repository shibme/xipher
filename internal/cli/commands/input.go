package commands

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unicode"

	"golang.org/x/term"
	"xipher.org/xipher"
)

const (
	pwdSpecialChars = "!@#$%^&*()_+="
	pwdLength       = 10
)

var errInvalidPassword = fmt.Errorf("%s: password must be at least %d characters long and include an uppercase letter, a lowercase letter, a number, and one of: %s", "xipher", pwdLength, pwdSpecialChars)

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

func getVisibleInput(prompt string) (string, error) {
	var input string
	if prompt != "" {
		fmt.Print(prompt)
	}
	_, err := fmt.Scanln(&input)
	return input, err
}

func getHiddenInputFromUser(prompt string) ([]byte, error) {
	fmt.Print("[Hidden] " + prompt)
	input, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return input, err
}

func getPasswordOrSecretKeyFromUser(confirm, ignorePolicyCheck bool) ([]byte, error) {
	initialPrompt := "Enter a Password/Secret Key: "
	passwordOrSecretKey, err := getHiddenInputFromUser(initialPrompt)
	if err != nil {
		return nil, err
	}
	if xipher.IsSecretKeyStr(string(passwordOrSecretKey)) {
		return passwordOrSecretKey, nil
	}
	if !ignorePolicyCheck {
		if err = pwdCheck(string(passwordOrSecretKey)); err != nil {
			return nil, err
		}
	}
	if confirm {
		if confirmPassword, err := getHiddenInputFromUser("Confirm Password/Secret Key: "); err != nil {
			return nil, err
		} else if !bytes.Equal(passwordOrSecretKey, confirmPassword) {
			return nil, fmt.Errorf("passwords do not match")
		}
	}
	return passwordOrSecretKey, nil
}

func readBufferFromStdin(prompt string) ([]byte, error) {
	var input []byte
	buffer := make([]byte, 1024)
	if prompt != "" {
		fmt.Println(prompt)
	}
	for {
		n, err := os.Stdin.Read(buffer)
		if err != nil || n == 0 {
			break
		}
		input = append(input, buffer[:n]...)
	}
	return input, nil
}
