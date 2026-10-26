// Package redisx is a minimal RESP2 client: just enough for pipelined writes and GET.
// It reconnects lazily; callers treat errors as "Redis unavailable" and carry on.
package redisx

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Client struct {
	Addr     string
	Password string
	DB       int
	Timeout  time.Duration

	mu   sync.Mutex
	conn net.Conn
	rd   *bufio.Reader
	wr   *bufio.Writer
}

type ReplyError string

func (e ReplyError) Error() string { return "redis: " + string(e) }

var Nil = errors.New("redis: nil")

func (c *Client) connect() error {
	if c.conn != nil {
		return nil
	}
	to := c.Timeout
	if to == 0 {
		to = 2 * time.Second
	}
	conn, err := net.DialTimeout("tcp", c.Addr, to)
	if err != nil {
		return err
	}
	c.conn, c.rd, c.wr = conn, bufio.NewReader(conn), bufio.NewWriter(conn)
	var init [][]string
	if c.Password != "" {
		init = append(init, []string{"AUTH", c.Password})
	}
	if c.DB != 0 {
		init = append(init, []string{"SELECT", strconv.Itoa(c.DB)})
	}
	if len(init) > 0 {
		if _, err := c.pipeline(init); err != nil {
			c.closeLocked()
			return err
		}
	}
	return nil
}

func (c *Client) closeLocked() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn, c.rd, c.wr = nil, nil, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

// Pipeline sends all commands and returns their replies. The first error reply is returned
// as err (replies are still all read so the connection stays in sync).
func (c *Client) Pipeline(cmds [][]string) ([]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connect(); err != nil {
		return nil, err
	}
	out, err := c.pipeline(cmds)
	var re ReplyError
	if err != nil && !errors.As(err, &re) {
		c.closeLocked() // I/O error: drop the connection, reconnect next time
	}
	return out, err
}

func (c *Client) Get(key string) (string, error) {
	r, err := c.Pipeline([][]string{{"GET", key}})
	if err != nil {
		return "", err
	}
	if r[0] == nil {
		return "", Nil
	}
	s, _ := r[0].(string)
	return s, nil
}

func (c *Client) pipeline(cmds [][]string) ([]any, error) {
	to := c.Timeout
	if to == 0 {
		to = 2 * time.Second
	}
	_ = c.conn.SetDeadline(time.Now().Add(to))
	for _, cmd := range cmds {
		fmt.Fprintf(c.wr, "*%d\r\n", len(cmd))
		for _, a := range cmd {
			fmt.Fprintf(c.wr, "$%d\r\n%s\r\n", len(a), a)
		}
	}
	if err := c.wr.Flush(); err != nil {
		return nil, err
	}
	out := make([]any, len(cmds))
	var firstErr error
	for i := range cmds {
		v, err := c.read()
		if err != nil {
			var re ReplyError
			if !errors.As(err, &re) {
				return nil, err
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		out[i] = v
	}
	return out, firstErr
}

func (c *Client) read() (any, error) {
	line, err := c.rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, fmt.Errorf("redis: short reply")
	}
	body := line[1 : len(line)-2]
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, ReplyError(body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil || n < -1 || n > 512<<20 {
			return nil, fmt.Errorf("redis: bad bulk length")
		}
		if n == -1 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.rd, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil || n < -1 || n > 1<<20 {
			return nil, fmt.Errorf("redis: bad array length")
		}
		if n == -1 {
			return nil, nil
		}
		arr := make([]any, n)
		for i := range arr {
			if arr[i], err = c.read(); err != nil {
				var re ReplyError
				if !errors.As(err, &re) {
					return nil, err
				}
			}
		}
		return arr, nil
	}
	return nil, fmt.Errorf("redis: unknown reply type %q", line[0])
}
