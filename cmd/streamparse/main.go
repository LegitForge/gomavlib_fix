// Package main parses a raw MAVLink byte stream and reports what it found, in
// the format scripts/mavstream.py produces for pymavlink.
//
// The two reports are meant to be diffed. Feeding both parsers the same bytes
// is the only way to tell a frame this library loses from a frame that never
// arrived:
//
//	tcpdump -i any -w arm.pcap udp port 14550
//	scripts/mavstream.py extract arm.pcap --port 14550 -o arm
//	scripts/mavstream.py parse arm -o arm.python.json
//	go run ./cmd/streamparse -stream arm -o arm.go.json
//	scripts/mavstream.py compare arm.python.json arm.go.json
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/bluenviron/gomavlib/v4/pkg/dialect"
	"github.com/bluenviron/gomavlib/v4/pkg/dialects/ardupilotmega"
	"github.com/bluenviron/gomavlib/v4/pkg/frame"
	"github.com/bluenviron/gomavlib/v4/pkg/message"
)

const readBufferSize = 65536

type datagram struct {
	Offset int     `json:"offset"`
	Length int     `json:"length"`
	Time   float64 `json:"time"`
	Src    string  `json:"src"`
	Dst    string  `json:"dst"`
}

type frameRecord struct {
	Offset     int    `json:"offset"`
	MsgID      uint32 `json:"msgid"`
	Type       string `json:"type"`
	SysID      byte   `json:"sysid"`
	CompID     byte   `json:"compid"`
	Seq        byte   `json:"seq"`
	PayloadLen int    `json:"payload_len"`
}

type errorRecord struct {
	Offset           int    `json:"offset"`
	Length           int    `json:"length"`
	Reason           string `json:"reason"`
	Hex              string `json:"hex"`
	StoppedAtMagic   bool   `json:"stopped_at_magic"`
	Datagram         *int   `json:"datagram"`
	OffsetInDatagram *int   `json:"offset_in_datagram"`
	DatagramLength   *int   `json:"datagram_length"`
	AtDatagramTail   bool   `json:"at_datagram_tail"`
}

type gapRecord struct {
	Source  string `json:"source"`
	Offset  int    `json:"offset"`
	Missing int    `json:"missing"`
}

type report struct {
	Parser             string         `json:"parser"`
	StreamBytes        int            `json:"stream_bytes"`
	Datagrams          int            `json:"datagrams"`
	Frames             int            `json:"frames"`
	Errors             int            `json:"errors"`
	SkippedBytes       int            `json:"skipped_bytes"`
	SeqGaps            int            `json:"seq_gaps"`
	FramesMissingBySeq int            `json:"frames_missing_by_seq"`
	FramesBySource     map[string]int `json:"frames_by_source"`
	MissingBySource    map[string]int `json:"missing_by_source"`
	FramesByType       map[string]int `json:"frames_by_type"`
	FramesByMsgID      map[string]int `json:"frames_by_msgid"`
	GapDetail          []gapRecord    `json:"gap_detail"`
	ErrorDetail        []errorRecord  `json:"error_detail"`
	FrameOffsets       []int          `json:"frame_offsets"`
}

// countingReader counts what the frame reader has pulled from the stream, so
// an offset can be recovered as read minus what is still sitting in the
// buffer.
type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func datagramOf(index []datagram, offset int) (int, int, int, bool) {
	i := sort.Search(len(index), func(i int) bool {
		return index[i].Offset+index[i].Length > offset
	})
	if i == len(index) || offset < index[i].Offset {
		return 0, 0, 0, false
	}
	return i, offset - index[i].Offset, index[i].Length, true
}

func loadIndex(name string) ([]datagram, error) {
	buf, err := os.ReadFile(name + ".idx")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var index []datagram
	err = json.Unmarshal(buf, &index)

	return index, err
}

func typeName(msg message.Message) string {
	if _, ok := msg.(*message.MessageRaw); ok {
		return fmt.Sprintf("UNKNOWN_%d", msg.GetID())
	}

	return fmt.Sprintf("%T", msg)
}

func run() error {
	streamName := flag.String("stream", "", "name given to mavstream.py extract, without extension")
	out := flag.String("o", "", "write the full report here")
	flag.Parse()

	if *streamName == "" {
		return fmt.Errorf("-stream is required")
	}

	stream, err := os.ReadFile(*streamName + ".bin")
	if err != nil {
		return err
	}

	index, err := loadIndex(*streamName)
	if err != nil {
		return err
	}

	dialectRW := &dialect.ReadWriter{Dialect: ardupilotmega.Dialect}
	err = dialectRW.Initialize()
	if err != nil {
		return err
	}

	counter := &countingReader{r: bytes.NewReader(stream)}
	buffered := bufio.NewReaderSize(counter, readBufferSize)

	reader := &frame.Reader{BufByteReader: buffered, DialectRW: dialectRW}
	err = reader.Initialize()
	if err != nil {
		return err
	}

	rep := report{
		Parser:          "gomavlib",
		StreamBytes:     len(stream),
		Datagrams:       len(index),
		FramesBySource:  map[string]int{},
		MissingBySource: map[string]int{},
		FramesByType:    map[string]int{},
		FramesByMsgID:   map[string]int{},
		GapDetail:       []gapRecord{},
		ErrorDetail:     []errorRecord{},
		FrameOffsets:    []int{},
	}

	lastSeq := map[string]byte{}

	for {
		offset := counter.read - buffered.Buffered()

		fr, rerr := reader.Read()
		if rerr != nil {
			var readErr frame.ReadError
			if !errors.As(rerr, &readErr) {
				if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
					break
				}
				return rerr
			}

			rec := errorRecord{
				Offset:         offset,
				Length:         counter.read - buffered.Buffered() - offset,
				Reason:         readErr.Error(),
				StoppedAtMagic: readErr.StoppedAtMagic,
			}
			if readErr.SkippedBytes != nil {
				rec.Hex = hex.EncodeToString(readErr.SkippedBytes[:min(64, len(readErr.SkippedBytes))])
			}
			if dg, into, dgLen, ok := datagramOf(index, offset); ok {
				rec.Datagram, rec.OffsetInDatagram, rec.DatagramLength = &dg, &into, &dgLen
				rec.AtDatagramTail = into+rec.Length >= dgLen
			}

			atEnd := counter.read == len(stream) && buffered.Buffered() == 0
			if atEnd && !readErr.StoppedAtMagic && readErr.SkippedBytes == nil {
				// a frame cut short by the end of the capture, not a fault
				break
			}

			rep.Errors++
			rep.SkippedBytes += rec.Length
			if len(rep.ErrorDetail) < 50 {
				rep.ErrorDetail = append(rep.ErrorDetail, rec)
			}

			continue
		}

		msg := fr.GetMessage()
		source := fmt.Sprintf("%d:%d", fr.GetSystemID(), fr.GetComponentID())

		if prev, ok := lastSeq[source]; ok {
			if missing := int(fr.GetSequenceNumber()-prev-1) & 0xFF; missing != 0 {
				if len(rep.GapDetail) < 50 {
					rep.GapDetail = append(rep.GapDetail,
						gapRecord{Source: source, Offset: offset, Missing: missing})
				}
				rep.SeqGaps++
				rep.FramesMissingBySeq += missing
				rep.MissingBySource[source] += missing
			}
		}
		lastSeq[source] = fr.GetSequenceNumber()

		rep.Frames++
		rep.FramesBySource[source]++
		rep.FramesByType[typeName(msg)]++
		rep.FramesByMsgID[fmt.Sprintf("%d", msg.GetID())]++
		rep.FrameOffsets = append(rep.FrameOffsets, offset)
	}

	encoded, err := json.MarshalIndent(rep, "", " ")
	if err != nil {
		return err
	}

	if *out != "" {
		err = os.WriteFile(*out, encoded, 0o600)
		if err != nil {
			return err
		}
	}

	fmt.Printf("parser %s: %d bytes, %d datagrams, %d frames, %d errors, "+
		"%d bytes skipped, %d seq gaps (%d frames)\n",
		rep.Parser, rep.StreamBytes, rep.Datagrams, rep.Frames, rep.Errors,
		rep.SkippedBytes, rep.SeqGaps, rep.FramesMissingBySeq)

	for _, e := range rep.ErrorDetail {
		tail := ""
		if e.Datagram != nil {
			tail = fmt.Sprintf(" (datagram %d, byte %d of %d)", *e.Datagram, *e.OffsetInDatagram, *e.DatagramLength)
		}
		fmt.Fprintf(os.Stderr, "  offset %d: %s%s\n    %s\n", e.Offset, e.Reason, tail, e.Hex)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
