package gomavlib

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStreamDumpRecordsDatagramsVerbatim(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "dump")
	t.Setenv(StreamDumpEnv, prefix)

	node, local := newDatagramNode(t)

	// three datagrams of different shapes, including one that does not begin on
	// a frame boundary: the dump has to hold the garbage too, otherwise it is
	// not the stream the parser saw.
	datagrams := [][]byte{
		encodeDatagram(t, 2),
		append(bytes.Repeat([]byte{0x46}, 50), encodeDatagram(t, 1)...),
		encodeDatagram(t, 1),
	}

	// the event channel and the dummy link are both unbuffered, so the writes
	// have to run alongside the drain or the reader stalls on the first event
	written := make(chan error, 1)
	go func() {
		for _, dg := range datagrams {
			if _, err := local.Write(dg); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()

	// drain until every frame behind the garbage has come through, so the
	// reader has consumed all three datagrams before the node is closed
	frames := 0
	for frames < 4 {
		if _, ok := (<-node.Events()).(*EventFrame); ok {
			frames++
		}
	}

	require.NoError(t, <-written)

	node.Close()

	binary, err := os.ReadFile(prefix + "-custom.bin")
	require.NoError(t, err)
	require.Equal(t, bytes.Join(datagrams, nil), binary)

	rawIndex, err := os.ReadFile(prefix + "-custom.idx")
	require.NoError(t, err)

	var index []streamDumpEntry
	err = json.Unmarshal(rawIndex, &index)
	require.NoError(t, err)
	require.Len(t, index, len(datagrams))

	offset := 0
	for i, dg := range datagrams {
		require.Equal(t, offset, index[i].Offset)
		require.Equal(t, len(dg), index[i].Length)
		require.Equal(t, dg, binary[index[i].Offset:index[i].Offset+index[i].Length])
		require.NotZero(t, index[i].Time)
		offset += len(dg)
	}
}

func TestStreamDumpOffByDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(StreamDumpEnv, "")

	node, local := newDatagramNode(t)

	// built outside the goroutine: encodeDatagram asserts, and require must not
	// be called off the test goroutine
	datagram := encodeDatagram(t, 1)

	written := make(chan error, 1)
	go func() {
		_, err := local.Write(datagram)
		written <- err
	}()

	for {
		if _, ok := (<-node.Events()).(*EventFrame); ok {
			break
		}
	}

	require.NoError(t, <-written)

	node.Close()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "no dump must be written when %s is unset", StreamDumpEnv)
}
