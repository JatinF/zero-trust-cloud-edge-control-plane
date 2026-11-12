package redact

import "regexp"

var (
	bearer = regexp.MustCompile(`Bearer\s+\S+`)
	token  = regexp.MustCompile(`lab-token-[A-Za-z0-9-]+`)
)

// Secret replaces bearer tokens and lab tokens before they are stored or returned.
func Secret(value string) string {
	value = bearer.ReplaceAllString(value, "Bearer [redacted]")
	return token.ReplaceAllString(value, "[redacted]")
}
