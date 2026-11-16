//go:build !e2efake

package telegram

// defaultBase is the only Telegram API address a release binary talks to.
func defaultBase() string { return "https://api.telegram.org" }
