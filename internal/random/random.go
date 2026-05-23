package random

import "github.com/aatuh/randutil/v2/randstring"

func Token(prefix string, bytes int) (string, error) {
	token, err := randstring.TokenURLSafe(bytes)
	if err != nil {
		return "", err
	}
	if prefix == "" {
		return token, nil
	}
	return prefix + "_" + token, nil
}
