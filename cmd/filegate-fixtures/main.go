package main

import (
	"os"

	"filegate.local/filegate/internal/fixtures"
)

func main() { os.Exit(fixtures.Main(os.Args[1:])) }
