package stationui

import (
	"embed"
	"io/fs"
)

//go:embed web/index.html web/app.js web/transport.js web/styles.css
var embeddedAssets embed.FS

func EmbeddedAssets() fs.FS {
	assets, err := fs.Sub(embeddedAssets, "web")
	if err != nil {
		panic(err)
	}
	return assets
}
