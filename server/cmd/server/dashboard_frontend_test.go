package main

import (
	"strings"
	"testing"
)

func TestStatsPollerRecoversAfterDashboardRestart(t *testing.T) {
	for _, want := range []string{"function scheduleReload()", "async function fetchJSON(url)", "AbortController", "Accept':'application/json'", "Syncing"} {
		if !strings.Contains(serverStatsHTML, want) {
			t.Fatalf("server stats template missing restart recovery fragment %q", want)
		}
	}
	if !strings.Contains(serverStatsHTML, "ok==='warn'") {
		t.Fatal("server stats template should support a warning pill state while status is resyncing")
	}
}