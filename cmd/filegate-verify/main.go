package main

import (
	"filegate.local/filegate/internal/verification"
	"os"
)

func main() { os.Exit(verification.VerifyMain(os.Args[1:])) }
