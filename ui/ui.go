package ui

import "embed"

//go:embed templates/*.html
var Templates embed.FS

//go:embed static/*
var StaticFiles embed.FS
