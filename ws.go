package main

// 最小 WebSocket 客户端，只够跟 Chrome DevTools Protocol 说话。
//
// 为什么不用现成库：项目只依赖 go-webview2，为了拿一次 Cookie 引入
// gorilla/websocket 不划算。这里实现 RFC 6455 客户端必需的部分：
//   - HTTP Upgrade 握手
//   - 客户端帧必须 mask
//   - 文本帧收发
//   - 分片重组
//   - ping/pong
//
// 不支持扩展、压缩、二进制流式推送（CDP 用不到）。

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	mu   sync.Mutex
}

// wsDial 建立 websocket 连接。wsURL 形如 ws://127.0.0.1:9222/devtools/page/XXX
func wsDial(wsURL string, timeout time.Duration) (*wsConn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" {
		return nil, fmt.Errorf("只支持 ws://，收到 %s", u.Scheme)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	// 随机 key
	raw := make([]byte, 16)
	rand.Read(raw)
	key := base64.StdEncoding.EncodeToString(raw)

	path := u.RequestURI()
	var req strings.Builder
	req.WriteString("GET " + path + " HTTP/1.1\r\n")
	req.WriteString("Host: " + u.Host + "\r\n")
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	req.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("握手失败 HTTP %d", resp.StatusCode)
	}
	h := sha1.New()
	h.Write([]byte(key + wsMagic))
	expect := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != expect {
		conn.Close()
		return nil, errors.New("Sec-WebSocket-Accept 校验失败")
	}

	conn.SetDeadline(time.Time{})
	return &wsConn{conn: conn, br: br}, nil
}

func (c *wsConn) Close() error { return c.conn.Close() }

// writeFrame 发一帧。客户端发送必须 mask。
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var hdr []byte
	hdr = append(hdr, 0x80|opcode) // FIN=1

	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(n))
		hdr = append(hdr, 0x80|127)
		hdr = append(hdr, b...)
	}

	mask := make([]byte, 4)
	rand.Read(mask)
	hdr = append(hdr, mask...)

	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.conn.Write(append(hdr, masked...)); err != nil {
		return err
	}
	return nil
}

// WriteText 发文本帧
func (c *wsConn) WriteText(s string) error { return c.writeFrame(0x1, []byte(s)) }

// ReadMessage 读一条完整消息（自动重组分片、应答 ping）
func (c *wsConn) ReadMessage(timeout time.Duration) (string, error) {
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	var buf []byte
	for {
		opcode, fin, payload, err := c.readFrame()
		if err != nil {
			return "", err
		}
		switch opcode {
		case 0x1, 0x0: // text / continuation
			buf = append(buf, payload...)
			if fin {
				return string(buf), nil
			}
		case 0x8: // close
			c.writeFrame(0x8, payload)
			return "", io.EOF
		case 0x9: // ping
			c.writeFrame(0xA, payload)
		case 0xA: // pong，忽略
		}
	}
}

func (c *wsConn) readFrame() (opcode byte, fin bool, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return
	}
	fin = h[0]&0x80 != 0
	opcode = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	length := int64(h[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}
	if length < 0 || length > 64<<20 {
		err = fmt.Errorf("帧长度异常 %d", length)
		return
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, maskKey[:]); err != nil {
			return
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return
}
