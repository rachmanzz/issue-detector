package web

import _ "embed"

//go:embed ui/index.html
var indexHTML string

//go:embed ui/app.js
var appJS string
