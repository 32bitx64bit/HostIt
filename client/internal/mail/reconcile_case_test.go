package mail

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"hostit/shared/emailcfg"
)

// TestReconcileMergesCaseVariantAccounts ensures that when the normalized
// (lowercase) email config is applied over a database that still holds a
// mixed-case account (e.g. "Alice" left over from an older database), the
// account is merged into the canonical "alice" instead of being duplicated,
// and its messages are reassigned so they still appear in the inbox.
func TestReconcileMergesCaseVariantAccounts(t *testing.T) {
	mailDir := t.TempDir()
	svc, err := NewService(mailDir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	// Seed a pre-normalization account + message under a mixed-case username.
	if _, err := svc.db.Exec(`INSERT INTO accounts(username, address, password_hash, enabled, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)`,
		"Alice", "Alice@example.com", string(hash), 1, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.db.Exec(`INSERT INTO messages(username, mailbox, internal_date, flags_json, raw, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		"Alice", "INBOX", 0, "[]", []byte("From: x@example.net\r\nTo: alice@example.com\r\nSubject: old\r\n\r\nbody"), 0); err != nil {
		t.Fatal(err)
	}

	if err := svc.ApplyConfig(emailcfg.Config{
		Enabled: true,
		Domain:  "example.com",
		Accounts: []emailcfg.Account{
			{Username: "alice", PasswordHash: string(hash), PasswordSet: true, Enabled: true},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Exactly one account row, under the canonical username.
	var nAccounts int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&nAccounts); err != nil {
		t.Fatal(err)
	}
	if nAccounts != 1 {
		t.Fatalf("accounts = %d, want 1 (case-variant not merged)", nAccounts)
	}

	st := svc.Status()
	if st.MessageCount != 1 {
		t.Fatalf("MessageCount = %d, want 1", st.MessageCount)
	}

	// The orphaned message must now be reachable from the canonical inbox.
	inbox, err := svc.ListInbox("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox) != 1 || inbox[0].Subject != "old" {
		t.Fatalf("ListInbox(alice) = %+v, want 1 message with subject %q", inbox, "old")
	}
}
