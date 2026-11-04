//go:build !darwin

package main

func openUI(string) bool { return false }
