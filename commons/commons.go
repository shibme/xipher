package commons

func StringPtr(s string) *string {
	return &s
}

func ByteSlicePtr(bytes []byte) *[]byte {
	return &bytes
}
