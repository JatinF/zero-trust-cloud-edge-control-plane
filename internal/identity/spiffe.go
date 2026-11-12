package identity

import "strings"

const prefix = "spiffe://syn.lab/"

func EdgeSPIFFE(edgeID string) string {
	return prefix + "edge/" + edgeID
}

func EndpointSPIFFE(endpointID string) string {
	return prefix + "endpoint/" + endpointID
}

func ParseSPIFFE(id string) (kind, name string, ok bool) {
	rest, found := strings.CutPrefix(id, prefix)
	if !found {
		return "", "", false
	}
	kind, name, found = strings.Cut(rest, "/")
	if !found || kind == "" || name == "" {
		return "", "", false
	}
	return kind, name, true
}
