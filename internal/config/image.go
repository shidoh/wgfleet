package config

import "strings"

// ResolveImage resolves a final "repository:tag" reference for a dockerized
// component from an operator's image + tag overrides, filling any unset part
// from def (a fully-qualified default like "spx01/blocky:latest").
//
// Every component the platform runs in Docker exposes an image and a tag knob so
// both can always be pinned. Precedence for the tag: an explicit tag wins; else
// a tag embedded in image wins; else the default's tag. The repository comes
// from image when set, else the default's.
func ResolveImage(image, tag, def string) string {
	repo, embTag := splitImageRef(image)
	drepo, dtag := splitImageRef(def)
	if repo == "" {
		repo = drepo
	}
	switch {
	case tag != "":
		// explicit tag wins
	case embTag != "":
		tag = embTag
	default:
		tag = dtag
	}
	if repo == "" {
		return ""
	}
	if tag == "" {
		return repo
	}
	return repo + ":" + tag
}

// splitImageRef splits "repo:tag" into its parts. A colon is only a tag
// separator when it appears after the last slash, so a registry port
// (e.g. "localhost:5000/img") is not mistaken for a tag.
func splitImageRef(ref string) (repo, tag string) {
	if ref == "" {
		return "", ""
	}
	lastColon := strings.LastIndex(ref, ":")
	lastSlash := strings.LastIndex(ref, "/")
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	return ref, ""
}
