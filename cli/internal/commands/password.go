package commands

import (
	"bytes"
	"fmt"
	"syscall"

	"golang.org/x/term"
)

func getPasswordFromUser(confirm bool) ([]byte, error) {
	fmt.Print("Enter Password:\t")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Println()
	if confirm {
		fmt.Print("Confirm Password:\t")
		confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		fmt.Println()
		if !bytes.Equal(password, confirmPassword) {
			return nil, fmt.Errorf("passwords do not match")
		}
	}
	return password, nil
}
