package kms

import _ "embed"

//go:embed web/consent.html
var consentPage []byte

//go:embed web/login.html
var loginPage []byte
