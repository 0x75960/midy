package midy

import (
	"regexp"
	"strings"
)

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

// RegexSomethingHash string
var RegexSomethingHash = regexp.MustCompile(
	`[[:^xdigit:]]([[:xdigit:]]{32}|[[:xdigit:]]{40}|[[:xdigit:]]{64})[[:^xdigit:]]`,
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

// ScrapeHashStrings from specified string
func ScrapeHashStrings(s string) (hashes []string) {
	sm := RegexSomethingHash.FindAllStringSubmatch(s, -1)
	for _, m := range sm {
		hashes = append(hashes, strings.ToLower(m[1]))
	}

	return
}

// EmptyHash check.
func EmptyHash(s string) (yes bool) {

	// see https://www.virustotal.com/#/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/details

	switch strings.ToLower(s) {
	case "d41d8cd98f00b204e9800998ecf8427e": // md5 empty
		fallthrough
	case "da39a3ee5e6b4b0d3255bfef95601890afd80709": // sha1 empty
		fallthrough
	case "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": // sha256 empty
		return true
	}

	return
}
