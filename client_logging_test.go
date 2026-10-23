package ldapserver

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientLogsOmitPacketContents(t *testing.T) {
	const password = "DoNotLog-BindSecret-Z9!qX~"
	var request struct {
		MessageID int
		Bind      struct {
			Version  int
			Name     []byte
			Password []byte `asn1:"tag:0"`
		} `asn1:"application,tag:0"`
	}
	request.MessageID = 1
	request.Bind.Version = 3
	request.Bind.Name = []byte("cn=log-test")
	request.Bind.Password = []byte(password)
	bindRequest, err := asn1.Marshal(request)
	if err != nil {
		t.Fatalf("encode bind request: %v", err)
	}
	malformed := append([]byte(nil), bindRequest...)
	// Overstate the password length while preserving the complete outer frame.
	malformed[len(malformed)-len(password)-1]++
	_, decodeErr := (&messagePacket{bytes: malformed}).readMessage()
	if decodeErr == nil {
		t.Fatal("expected the malformed bind to fail decoding")
	}

	var logs bytes.Buffer
	previousLogger := Logger
	Logger = log.New(&logs, "", 0)
	t.Cleanup(func() { Logger = previousLogger })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := NewServer()
	routes := NewRouteMux()
	routes.Bind(func(w ResponseWriter, m *Message) {
		res := NewBindResponse(LDAPResultSuccess)
		// Echo the password only in this fixture to exercise outbound logging.
		bind := m.GetBindRequest()
		res.SetDiagnosticMessage(string(bind.AuthenticationSimple()))
		w.Write(res)
	})
	server.Handle(routes)
	server.Listener = ln
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.serve() }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			server.Stop()
			if err := <-serveDone; err != nil {
				t.Errorf("serve: %v", err)
			}
		})
	}
	t.Cleanup(stop)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(bindRequest); err != nil {
		t.Fatalf("write bind request: %v", err)
	}
	br := bufio.NewReader(conn)
	responsePacket, err := readMessagePacket(br)
	if err != nil {
		t.Fatalf("read bind response: %v", err)
	}
	response, err := responsePacket.readMessage()
	if err != nil {
		t.Fatalf("decode bind response: %v", err)
	}
	if response.ProtocolOpName() != "BindResponse" {
		t.Fatalf("expected BindResponse, got %s", response.ProtocolOpName())
	}
	if !bytes.Contains(responsePacket.bytes, []byte(password)) {
		t.Fatal("response fixture did not contain the password")
	}
	if _, err := conn.Write(malformed); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}
	// An invalid next tag closes the connection after the decode error is logged.
	if _, err := conn.Write([]byte{0xde}); err != nil {
		t.Fatalf("write invalid tag: %v", err)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("expected connection close, got %v", err)
	}
	stop()

	output := logs.String()
	for _, want := range []string{
		"<<< 1 - BindRequest",
		">>> 1 - BindResponse",
		"Error reading Message : " + decodeErr.Error(),
		"Error readMessagePacket: Expecting 0x30 as first byte",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("missing log message %q", want)
		}
	}
	for _, forbidden := range []struct {
		name  string
		value string
	}{
		{"plaintext password", password},
		{"lowercase password hex", hex.EncodeToString([]byte(password))},
		{"uppercase password hex", strings.ToUpper(hex.EncodeToString([]byte(password)))},
		{"inbound packet hex", hex.EncodeToString(bindRequest)},
		{"outbound packet hex", hex.EncodeToString(responsePacket.bytes)},
		{"malformed packet hex", hex.EncodeToString(malformed)},
		{"invalid header byte", "0xde"},
		{"hex payload label", "hex="},
	} {
		if strings.Contains(output, forbidden.value) {
			t.Errorf("logs contain %s", forbidden.name)
		}
	}
}
