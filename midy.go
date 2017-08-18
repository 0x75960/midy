package midy

import "regexp"

// RegexValidMd5 for judge
var RegexValidMd5 = regexp.MustCompile(
	`^([[:xdigit:]]{32})$`,
)

// RegexValidSha1 for judge
var RegexValidSha1 = regexp.MustCompile(
	`^([[:xdigit:]]{40})$`,
)

// RegexValidSha256 for judge
var RegexValidSha256 = regexp.MustCompile(
	`^([[:xdigit:]]{64})$`,
)

// HashType to judge
type HashType int

const (

	// Invalid HashType
	Invalid HashType = iota

	// Md5 hash
	Md5

	// Sha1 hash
	Sha1

	// Sha256 hash
	Sha256
)

// DetectHashType of string
func DetectHashType(s string) (h HashType) {

	switch {

	case RegexValidMd5.MatchString(s):
		return Md5

	case RegexValidSha1.MatchString(s):
		return Sha1

	case RegexValidSha256.MatchString(s):
		return Sha256

	default:

	}

	return
}
