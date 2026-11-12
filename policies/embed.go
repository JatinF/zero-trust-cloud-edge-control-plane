package policies

import _ "embed"

//go:embed access.rego
var Access string

//go:embed privileged.rego
var Privileged string
