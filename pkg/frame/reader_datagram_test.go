package frame

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bluenviron/gomavlib/v4/pkg/message"
)

// oneShotReader hands out its entire content in a single Read, like a datagram
// socket does: whatever does not fit into the given buffer is lost.
type oneShotReader struct {
	buf  []byte
	done bool
}

func (r *oneShotReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.buf), nil
}

func TestReaderMultipleFramesInSingleRead(t *testing.T) {
	const frameCount = 100

	var buf bytes.Buffer

	writer := &Writer{ByteWriter: &buf}
	err := writer.Initialize()
	require.NoError(t, err)

	for i := range frameCount {
		err = writer.Write(&V2Frame{
			SequenceNumber: byte(i),
			SystemID:       11,
			ComponentID:    1,
			Message: &message.MessageRaw{
				ID:      5,
				Payload: []byte{byte(i), 1, 2, 3, 4, 5, 6, 7},
			},
		})
		require.NoError(t, err)
	}

	// the point of the test: the frames do not fit into a single-frame buffer
	require.Greater(t, buf.Len(), maxFrameSize)

	reader := &Reader{
		BufByteReader: bufio.NewReaderSize(&oneShotReader{buf: buf.Bytes()}, readBufferSize),
	}
	err = reader.Initialize()
	require.NoError(t, err)

	for i := range frameCount {
		var fr Frame
		fr, err = reader.Read()
		require.NoError(t, err)
		require.Equal(t, byte(i), fr.(*V2Frame).SequenceNumber)
		require.Equal(t, []byte{byte(i), 1, 2, 3, 4, 5, 6, 7}, fr.GetMessage().(*message.MessageRaw).Payload)
	}

	_, err = reader.Read()
	require.Equal(t, io.EOF, err)
}
