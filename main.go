package main

import (
    "github.com/hashicorp/vault/plugins"
)

func main() {
	plugins.Serve(New().(*RedShift), nil)
}