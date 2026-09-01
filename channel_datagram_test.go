package gomavlib

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bluenviron/gomavlib/v4/pkg/dialect"
	"github.com/bluenviron/gomavlib/v4/pkg/frame"
	"github.com/bluenviron/gomavlib/v4/pkg/streamwriter"
)

// encodeDatagram packs count heartbeats into a single buffer, the way a sender
// that batches messages fills one datagram.
func encodeDatagram(t *testing.T, count int) []byte {
	t.Helper()

	dialectRW := &dialect.ReadWriter{Dialect: testDialect}
	err := dialectRW.Initialize()
	require.NoError(t, err)

	var buf bytes.Buffer

	fw := &frame.Writer{ByteWriter: &buf, DialectRW: dialectRW}
	err = fw.Initialize()
	require.NoError(t, err)

	sw := &streamwriter.Writer{
		FrameWriter: fw,
		Version:     streamwriter.V2,
		SystemID:    11,
	}
	err = sw.Initialize()
	require.NoError(t, err)

	for range count {
		err = sw.Write(&MessageHeartbeat{
			Type:           1,
			Autopilot:      2,
			BaseMode:       3,
			CustomMode:     6,
			SystemStatus:   4,
			MavlinkVersion: 5,
		})
		require.NoError(t, err)
	}

	return buf.Bytes()
}

func newDatagramNode(t *testing.T) (*Node, *dummyReadWriter) {
	t.Helper()

	remote, local := newDummyReadWriterPair()

	node := &Node{
		Dialect:          testDialect,
		OutVersion:       V2,
		OutSystemID:      10,
		HeartbeatDisable: true,
		Endpoints: []Endpoint{&EndpointCustomClient{
			Connect: func(_ context.Context) (net.Conn, error) {
				return &rwcToConn{remote}, nil
			},
			IsDatagram: true,
		}},
	}
	err := node.Initialize()
	require.NoError(t, err)

	evt := <-node.Events()
	require.Equal(t, &EventChannelOpen{
		Channel: evt.(*EventChannelOpen).Channel,
	}, evt)

	return node, local
}

func TestChannelDatagramMultipleFrames(t *testing.T) {
	const frameCount = 30

	node, local := newDatagramNode(t)
	defer node.Close()

	_, err := local.Write(encodeDatagram(t, frameCount))
	require.NoError(t, err)

	for i := range frameCount {
		evt := <-node.Events()
		fr, ok := evt.(*EventFrame)
		require.True(t, ok, "expected a frame, got %T", evt)
		require.Equal(t, byte(i), fr.Frame.(*frame.V2Frame).SequenceNumber)
	}
}

func TestChannelDatagramFrameSplitAcrossDatagrams(t *testing.T) {
	const frameCount = 30

	node, local := newDatagramNode(t)
	defer node.Close()

	// cut the batch in the middle of a frame, the way ArduPilot does when its
	// ring buffer wraps: the frame has to be reassembled across the boundary
	batch := encodeDatagram(t, frameCount)
	cut := len(batch)/2 + 7

	writeErr := make(chan error, 2)
	go func() {
		_, err := local.Write(batch[:cut])
		writeErr <- err
		_, err = local.Write(batch[cut:])
		writeErr <- err
	}()

	for i := range frameCount {
		evt := <-node.Events()
		fr, ok := evt.(*EventFrame)
		require.True(t, ok, "expected a frame, got %T", evt)
		require.Equal(t, byte(i), fr.Frame.(*frame.V2Frame).SequenceNumber)
	}

	require.NoError(t, <-writeErr)
	require.NoError(t, <-writeErr)
}

func TestChannelDatagramResyncAfterGarbage(t *testing.T) {
	node, local := newDatagramNode(t)
	defer node.Close()

	// a datagram that does not begin on a frame boundary: the leading bytes are
	// reported once and skipped, and the frames behind them still get through
	datagram := append(bytes.Repeat([]byte{0x00}, 64), encodeDatagram(t, 2)...)
	_, err := local.Write(datagram)
	require.NoError(t, err)

	evt := <-node.Events()
	parseErr, ok := evt.(*EventParseError)
	require.True(t, ok, "expected a parse error, got %T", evt)
	require.ErrorContains(t, parseErr.Error, "skipped 63 bytes")

	var readErr frame.ReadError
	require.ErrorAs(t, parseErr.Error, &readErr)
	require.True(t, readErr.StoppedAtMagic)
	require.Equal(t, bytes.Repeat([]byte{0x00}, 64), readErr.SkippedBytes)

	for i := range 2 {
		evt = <-node.Events()
		fr, frOk := evt.(*EventFrame)
		require.True(t, frOk, "expected a frame, got %T", evt)
		require.Equal(t, byte(i), fr.Frame.(*frame.V2Frame).SequenceNumber)
	}
}
