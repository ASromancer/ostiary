//go:build e2efake

package telegram

import "os"

// defaultBase honours OSTIARY_E2E_TELEGRAM_URL so the e2e test can point the
// daemon at a fake Bot API. Test builds only, never in releases.
func defaultBase() string {
	if u := os.Getenv("OSTIARY_E2E_TELEGRAM_URL"); u != "" {
		return u
	}
	return "https://api.telegram.org"
}
