package gomavlib

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// StreamDumpEnv is the environment variable that turns raw stream dumping on.
// It holds a path prefix; each datagram channel writes "<prefix>-<label>.bin"
// and "<prefix>-<label>.idx" next to each other.
const StreamDumpEnv = "GOMAVLIB_STREAM_DUMP"

// How often the index is rewritten while the channel is running. The index is
// only useful together with the bytes it describes, and rewriting it on every
// datagram would be wasteful at telemetry rates, so it is flushed on a timer
// and again when the channel closes.
const streamDumpFlushPeriod = 500 * time.Millisecond

// streamDumpEntry describes one datagram inside the dumped byte stream. The
// field names are the ones scripts/mavstream.py writes, so the two tools are
// interchangeable and cmd/streamparse reads either.
type streamDumpEntry struct {
	Offset int     `json:"offset"`
	Length int     `json:"length"`
	Time   float64 `json:"time"`
	Src    string  `json:"src"`
	Dst    string  `json:"dst"`
}

// streamDump records the datagrams of one channel exactly as they arrived,
// producing the same pair of files as "mavstream.py extract" does from a pcap.
//
// Capturing on the host is the obvious way to get these bytes, but it needs a
// capture driver, administrator rights and an interface that can actually be
// tapped — none of which hold when the link runs over a WireGuard tunnel. Here
// the datagram is already whole and its boundary is already known, so the same
// data comes out without any of that, and without the risk of a capture
// dropping or truncating a packet.
//
// One dump belongs to one channel, so a single file never interleaves two
// sources; interleaved sources desynchronise any parser, which is the failure
// "mavstream.py extract --src" exists to avoid.
type streamDump struct {
	src string
	dst string

	mutex     sync.Mutex
	bin       *os.File
	idxPath   string
	entries   []streamDumpEntry
	offset    int
	lastFlush time.Time
	closed    bool
}

// newStreamDump returns nil when dumping is off, which is the normal case.
func newStreamDump(label string) (*streamDump, error) {
	prefix := os.Getenv(StreamDumpEnv)
	if prefix == "" {
		return nil, nil //nolint:nilnil
	}

	name := prefix + "-" + sanitizeForFilename(label)

	bin, err := os.Create(name + ".bin") //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("create stream dump: %w", err)
	}

	return &streamDump{
		// The channel label is all the identity available here: the connection
		// is wrapped by the time it reaches this layer and no longer exposes
		// its addresses. It is only ever informational — both parsers locate a
		// datagram by offset and length.
		src:     strings.TrimPrefix(label, "udp:"),
		dst:     "",
		bin:     bin,
		idxPath: name + ".idx",
	}, nil
}

// add records one datagram. The payload is copied into the file immediately,
// so the caller is free to reuse the buffer.
func (d *streamDump) add(payload []byte) {
	if d == nil {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.closed {
		return
	}

	n, err := d.bin.Write(payload)
	if err != nil {
		return
	}

	d.entries = append(d.entries, streamDumpEntry{
		Offset: d.offset,
		Length: n,
		Time:   float64(time.Now().UnixNano()) / 1e9,
		Src:    d.src,
		Dst:    d.dst,
	})
	d.offset += n

	if time.Since(d.lastFlush) >= streamDumpFlushPeriod {
		d.writeIndexUnsafe()
		d.lastFlush = time.Now()
	}
}

func (d *streamDump) close() {
	if d == nil {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.closed {
		return
	}
	d.closed = true

	d.writeIndexUnsafe()
	d.bin.Close()
}

// writeIndexUnsafe rewrites the index through a temporary file, so a dump read
// while the run is still going, or after the process was killed, never sees a
// half-written index.
func (d *streamDump) writeIndexUnsafe() {
	encoded, err := json.MarshalIndent(d.entries, "", " ")
	if err != nil {
		return
	}

	tmp := d.idxPath + ".tmp"

	err = os.WriteFile(tmp, encoded, 0o600)
	if err != nil {
		return
	}

	os.Rename(tmp, d.idxPath) //nolint:errcheck
}

func sanitizeForFilename(in string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, in)
}
