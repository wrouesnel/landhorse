package sshkeys_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/wrouesnel/landhorse/pkg/backend"
	"github.com/wrouesnel/landhorse/pkg/sshkeys"
)

// startAgent serves an in-memory SSH agent on a socket in a temporary directory.
func startAgent(t *testing.T) (string, agent.Agent) {
	t.Helper()
	keyring := agent.NewKeyring()
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn); _ = conn.Close() }()
		}
	}()
	return socket, keyring
}

func TestAgentCategory(t *testing.T) {
	ctx := context.Background()
	socket, keyring := startAgent(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "me@laptop"}); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	group := &sshkeys.Group{AgentSocket: socket}
	cats, _ := group.Categories(ctx)
	if len(cats) != 2 || cats[1].Title() != "SSH agent" {
		t.Fatalf("categories: %v", cats)
	}
	items, err := cats[1].Items(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("agent items: %v, %v", items, err)
	}
	item := items[0]
	cells := item.Cells()
	if cells[0] != "me@laptop" || cells[1] != "Ed25519 256" || cells[2] != fingerprint {
		t.Errorf("cells: %v", cells)
	}
	if keys := item.(backend.Linkable).LinkKeys(); len(keys) != 1 || keys[0] != "ssh-fingerprint:"+fingerprint {
		t.Errorf("link keys: %v", keys)
	}
	text, _ := item.(backend.Copier).CopyText(ctx)
	if want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " me@laptop\n"; text != want {
		t.Errorf("copied %q, want %q", text, want)
	}

	if err := item.(backend.Deleter).Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if left, _ := keyring.List(); len(left) != 0 {
		t.Errorf("%d keys left in the agent after removing", len(left))
	}
}

func TestNoAgentNoCategory(t *testing.T) {
	cats, _ := (&sshkeys.Group{}).Categories(context.Background())
	if len(cats) != 1 {
		t.Errorf("got %d categories without an agent, want 1", len(cats))
	}
}

func TestUnreachableAgentIsAnError(t *testing.T) {
	cat := &sshkeys.AgentCategory{Socket: filepath.Join(t.TempDir(), "missing.sock")}
	if _, err := cat.Items(context.Background()); err == nil {
		t.Error("listing an unreachable agent succeeded")
	}
}
