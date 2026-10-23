package ldapserver

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	ldap "github.com/vjeantet/goldap/message"
)

func bindRequestWithName(t *testing.T, name string) []byte {
	t.Helper()

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
	request.Bind.Name = []byte(name)
	request.Bind.Password = []byte("secret")
	data, err := asn1.Marshal(request)
	if err != nil {
		t.Fatalf("encode bind request: %v", err)
	}
	return data
}

func TestReadMessagePacket(t *testing.T) {
	longName := "cn=" + strings.Repeat("x", 7000)
	largeRequest := bindRequestWithName(t, longName)
	for _, tt := range []struct {
		name       string
		request    []byte
		bindName   string
		fragmented bool
	}{
		{"small", rawBindRequest, "cn=test", false},
		{"small fragmented", rawBindRequest, "cn=test", true},
		{"large", largeRequest, longName, false},
		{"large fragmented", largeRequest, longName, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stream := append(append([]byte(nil), tt.request...), rawBindRequest...)
			var reader io.Reader = bytes.NewReader(stream)
			if tt.fragmented {
				reader = iotest.OneByteReader(reader)
			}
			br := bufio.NewReader(reader)
			packet, err := readMessagePacket(br)
			if err != nil {
				t.Fatalf("read packet: %v", err)
			}
			if !bytes.Equal(packet.bytes, tt.request) {
				t.Fatal("packet differs from the request")
			}
			message, err := decodeMessage(packet.bytes)
			if err != nil {
				t.Fatalf("decode packet: %v", err)
			}
			bind, ok := message.ProtocolOp().(ldap.BindRequest)
			if !ok {
				t.Fatalf("expected BindRequest, got %s", message.ProtocolOpName())
			}
			if string(bind.Name()) != tt.bindName || string(bind.AuthenticationSimple()) != "secret" {
				t.Fatal("decoded bind fields differ from the request")
			}

			packet, err = readMessagePacket(br)
			if err != nil {
				t.Fatalf("read next packet: %v", err)
			}
			if !bytes.Equal(packet.bytes, rawBindRequest) {
				t.Fatal("next packet differs from the request")
			}
		})
	}
}

func TestReadMessagePacketTruncated(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"tag only", []byte{0x30}},
		{"missing long length", []byte{0x30, 0x82}},
		{"partial long length", []byte{0x30, 0x82, 0x1b}},
		{"missing body", rawBindRequest[:2]},
		{"partial body", rawBindRequest[:len(rawBindRequest)-1]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readMessagePacket(bufio.NewReader(bytes.NewReader(tt.data)))
			if err == nil {
				t.Fatal("expected an error for a truncated packet")
			}
		})
	}
}

func TestReadMessagePacketTimeout(t *testing.T) {
	want := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, tt := range []struct {
		name   string
		prefix []byte
	}{
		{"tag", nil},
		{"length", rawBindRequest[:1]},
		{"long length", []byte{0x30, 0x82, 0x1b}},
		{"body", rawBindRequest[:7]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader := io.MultiReader(bytes.NewReader(tt.prefix), iotest.ErrReader(want))
			_, err := readMessagePacket(bufio.NewReader(reader))
			if err != want {
				t.Fatalf("expected original timeout error, got %v", err)
			}
		})
	}
}

func TestReadMessagePacketAllocation(t *testing.T) {
	// Claim 16 MiB but send only one body byte before timing out.
	data := []byte{0x30, 0x84, 0x01, 0x00, 0x00, 0x00, 0x02}
	want := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(data), iotest.ErrReader(want)))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := readMessagePacket(br)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("allocated %d bytes for a one-byte body", allocated)
	}
	if err != want {
		t.Fatalf("expected original timeout error, got %v", err)
	}
}

func TestFragmentedLargeBindRequest(t *testing.T) {
	_, addr, stop := listenOnAvailablePort(t)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	largeRequest := bindRequestWithName(t, "cn="+strings.Repeat("x", 7000))
	br := bufio.NewReader(conn)
	for _, request := range [][]byte{largeRequest, rawBindRequest} {
		for offset := 0; offset < len(request); {
			end := min(offset+256, len(request))
			n, err := conn.Write(request[offset:end])
			if err != nil {
				t.Fatalf("write bind request: %v", err)
			}
			if n != end-offset {
				t.Fatalf("short write: %d of %d bytes", n, end-offset)
			}
			offset = end
			if offset < len(request) {
				time.Sleep(5 * time.Millisecond)
			}
		}

		packet, err := readMessagePacket(br)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		response, err := decodeMessage(packet.bytes)
		if err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.ProtocolOpName() != "BindResponse" {
			t.Fatalf("expected BindResponse, got %s", response.ProtocolOpName())
		}
		if response.MessageID().Int() != 1 {
			t.Fatalf("expected messageID=1, got %d", response.MessageID())
		}
	}
}
