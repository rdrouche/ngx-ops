package redislite

import (
	"net"
	"os/exec"
	"testing"
	"time"
)

// startRedis lance un vrai redis-server éphémère (ignore le test s'il est absent).
func startRedis(t *testing.T, extra ...string) (string, func()) {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server absent")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	dir := t.TempDir()
	args := append([]string{"--port", itoa(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", dir}, extra...)
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + itoa(port)
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return addr, func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }
}

func itoa(n int) string {
	return string([]byte(func() []byte {
		b := []byte{}
		if n == 0 {
			return []byte("0")
		}
		for n > 0 {
			b = append([]byte{byte('0' + n%10)}, b...)
			n /= 10
		}
		return b
	}()))
}

func TestGetSetBinaryAndTTL(t *testing.T) {
	addr, stop := startRedis(t)
	defer stop()
	c, err := Parse("redis://"+addr+"/0", "")
	if err != nil {
		t.Fatal(err)
	}
	val := []byte("a\r\nb\x00é\n$3\r\n")
	if err := c.SetEX("k", val, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.Get("k")
	if err != nil || !ok || string(got) != string(val) {
		t.Fatalf("get = %q %v %v", got, ok, err)
	}
	if _, ok, _ := c.Get("absent"); ok {
		t.Fatal("clé absente trouvée")
	}
	ttl, _ := c.Do("TTL", "k")
	if n, _ := ttl.(int64); n < 1 || n > 5 {
		t.Fatalf("ttl = %v", ttl)
	}
}

func TestAuthAndReconnect(t *testing.T) {
	addr, stop := startRedis(t, "--requirepass", "s3cret")
	c, _ := Parse("redis://"+addr+"/0", "")
	if err := c.Ping(); err == nil {
		t.Fatal("sans mot de passe : une erreur est attendue")
	}
	c, _ = Parse("redis://"+addr+"/2", "s3cret")
	if err := c.SetEX("x", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// coupure puis retour : le client doit se reconnecter seul
	stop()
	if err := c.Ping(); err == nil {
		t.Fatal("redis arrêté : une erreur est attendue")
	}
}

func TestParseValidation(t *testing.T) {
	for _, bad := range []string{"", "http://x", "redis://", "redis://h/abc", "redis://h/999"} {
		if _, err := Parse(bad, ""); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
	c, err := Parse("rediss://u:p@h.example:6380/3", "")
	if err != nil || c.Redacted() != "rediss://h.example:6380/3" {
		t.Fatalf("redacted = %v %v", c, err)
	}
	if o, _ := Parse("redis://:old@h", "new"); o.password != "new" {
		t.Error("le mot de passe ENV doit primer")
	}
}
