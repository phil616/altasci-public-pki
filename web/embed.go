// Package webassets embeds the production frontend in the application binary.
package webassets

import (
	"embed"
	"io/fs"
)

// The dist-placeholder.txt file lets package tests run before the frontend build.
// MountFrontend rejects a binary without the built index.html at startup.
//
//go:embed all:dist*
var files embed.FS

func Files() fs.FS {
	assets, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	return assets
}
