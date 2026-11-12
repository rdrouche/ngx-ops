// Package redislite : client Redis minimal (protocole RESP2) sans dépendance.
//
// Redis est OPTIONNEL dans NGX Ops : ce client ne sert qu'à conserver des
// états volatils (compteurs, suivi des IP en échec…) à travers un redémarrage.
// Toute erreur est renvoyée à l'appelant, qui doit dégrader sans bloquer
// (délais courts : 1,5 s par commande, 2 s pour se connecter).
package redislite

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client : une connexion unique, protégée par un mutex, reconnectée à la demande.
type Client struct {
	addr     string
	password string
	user     string
	db       int
	useTLS   bool
	host     string

	mu   sync.Mutex
	conn net.Conn
	br   *bufio.Reader

	Dial      func(network, addr string, timeout time.Duration) (net.Conn, error)
	CmdTimout time.Duration
}

// Parse lit redis://[user:pass@]host[:port][/db] ou rediss://… ; `password`
// (variable d'environnement dédiée) prime sur celui de l'URL. Les secrets ne
// doivent jamais être journalisés : utiliser Redacted() pour afficher l'URL.
func Parse(raw, password string) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") || u.Hostname() == "" {
		return nil, errors.New("URL Redis invalide (attendu : redis://hôte[:port][/db])")
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	c := &Client{addr: net.JoinHostPort(u.Hostname(), port), host: u.Hostname(), useTLS: u.Scheme == "rediss", CmdTimout: 1500 * time.Millisecond}
	if u.User != nil {
		c.user = u.User.Username()
		if p, ok := u.User.Password(); ok {
			c.password = p
		}
	}
	if password != "" {
		c.password = password
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return nil, errors.New("numéro de base Redis invalide")
		}
		c.db = n
	}
	c.Dial = func(network, addr string, t time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, addr, t)
	}
	return c, nil
}

// Redacted : adresse sans identifiants, pour les journaux.
func (c *Client) Redacted() string {
	s := "redis://"
	if c.useTLS {
		s = "rediss://"
	}
	return s + c.addr + "/" + strconv.Itoa(c.db)
}

func (c *Client) connect() error {
	conn, err := c.Dial("tcp", c.addr, 2*time.Second)
	if err != nil {
		return err
	}
	if c.useTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: c.host, MinVersion: tls.VersionTLS12})
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := tc.Handshake(); err != nil {
			conn.Close()
			return err
		}
		conn = tc
	}
	c.conn, c.br = conn, bufio.NewReader(conn)
	if c.password != "" {
		args := []string{"AUTH", c.password}
		if c.user != "" {
			args = []string{"AUTH", c.user, c.password}
		}
		if _, err := c.roundtrip(args); err != nil {
			c.close()
			return err
		}
	}
	if c.db != 0 {
		if _, err := c.roundtrip([]string{"SELECT", strconv.Itoa(c.db)}); err != nil {
			c.close()
			return err
		}
	}
	return nil
}

func (c *Client) close() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn, c.br = nil, nil
}

// Close ferme la connexion.
func (c *Client) Close() { c.mu.Lock(); c.close(); c.mu.Unlock() }

func (c *Client) roundtrip(args []string) (any, error) {
	_ = c.conn.SetDeadline(time.Now().Add(c.CmdTimout))
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b.WriteString("$" + strconv.Itoa(len(a)) + "\r\n" + a + "\r\n")
	}
	if _, err := io.WriteString(c.conn, b.String()); err != nil {
		return nil, err
	}
	return readReply(c.br, 0)
}

// ErrRedis : réponse d'erreur du serveur (la connexion reste saine).
type ErrRedis string

func (e ErrRedis) Error() string { return "redis: " + string(e) }

func readReply(br *bufio.Reader, depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("réponse trop imbriquée")
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, errors.New("réponse invalide")
	}
	body := strings.TrimRight(line[1:], "\r\n")
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, ErrRedis(body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil || n > 512<<20 {
			return nil, errors.New("taille de réponse invalide")
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		return buf[:n], nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil || n > 1<<20 {
			return nil, errors.New("taille de tableau invalide")
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := readReply(br, depth+1)
			if err != nil {
				if _, ok := err.(ErrRedis); !ok {
					return nil, err
				}
				v = err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("type de réponse inconnu %q", line[0])
}

// Do envoie une commande ; reconnecte une fois si la connexion était tombée.
func (c *Client) Do(args ...string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.conn == nil {
			if err := c.connect(); err != nil {
				return nil, err
			}
		}
		v, err := c.roundtrip(args)
		if err == nil {
			return v, nil
		}
		if _, ok := err.(ErrRedis); ok {
			return nil, err
		}
		c.close() // erreur réseau : on retente une fois sur une connexion neuve
	}
	return nil, errors.New("redis injoignable")
}

// Ping vérifie la connexion.
func (c *Client) Ping() error { _, err := c.Do("PING"); return err }

// Get renvoie (valeur, présente, erreur).
func (c *Client) Get(key string) ([]byte, bool, error) {
	v, err := c.Do("GET", key)
	if err != nil {
		return nil, false, err
	}
	b, _ := v.([]byte)
	return b, v != nil, nil
}

// SetEX écrit key=val avec une durée de vie (≥ 1 s).
func (c *Client) SetEX(key string, val []byte, ttl time.Duration) error {
	sec := int64(ttl / time.Second)
	if sec < 1 {
		sec = 1
	}
	_, err := c.Do("SET", key, string(val), "EX", strconv.FormatInt(sec, 10))
	return err
}
