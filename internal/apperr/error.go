package apperr

import "errors"

// Error is a stable application failure. Code is safe to return to callers.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func New(code, message string, status int) *Error {
	return &Error{Code: code, Message: message, Status: status}
}

func As(err error) (*Error, bool) {
	var target *Error
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}
