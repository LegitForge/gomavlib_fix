package frame

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bluenviron/gomavlib/v4/pkg/message"
)

// A run of skipped bytes says nothing on its own about what follows it: the
// scan stops either on a magic byte or on running out of buffered data, and
// only the second case leaves the rest of the link unaccounted for.
func TestReaderResyncStopReason(t *testing.T) {
	var buf bytes.Buffer

	writer := &Writer{ByteWriter: &buf}
	err := writer.Initialize()
	require.NoError(t, err)

	err = writer.Write(&V2Frame{
		SequenceNumber: 1,
		SystemID:       11,
		ComponentID:    1,
		Message: &message.MessageRaw{
			ID:      5,
			Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
	})
	require.NoError(t, err)

	garbage := bytes.Repeat([]byte{0x46}, 50)

	t.Run("stopped at magic byte", func(t *testing.T) {
		stream := append(append([]byte{}, garbage...), buf.Bytes()...)

		reader := &Reader{BufByteReader: bufio.NewReaderSize(bytes.NewReader(stream), readBufferSize)}
		err2 := reader.Initialize()
		require.NoError(t, err2)

		_, err2 = reader.Read()

		var readErr ReadError
		require.ErrorAs(t, err2, &readErr)
		require.True(t, readErr.StoppedAtMagic)
		require.Equal(t, garbage, readErr.SkippedBytes)
		require.ErrorContains(t, err2, "skipped 49 bytes; stopped at magic byte")

		// the frame behind the garbage survives
		fr, err2 := reader.Read()
		require.NoError(t, err2)
		require.Equal(t, byte(1), fr.(*V2Frame).SequenceNumber)
	})

	t.Run("buffer exhausted", func(t *testing.T) {
		reader := &Reader{BufByteReader: bufio.NewReaderSize(bytes.NewReader(garbage), readBufferSize)}
		err2 := reader.Initialize()
		require.NoError(t, err2)

		_, err2 = reader.Read()

		var readErr ReadError
		require.ErrorAs(t, err2, &readErr)
		require.False(t, readErr.StoppedAtMagic)
		require.Equal(t, garbage, readErr.SkippedBytes)
		require.Zero(t, readErr.Buffered)
		require.ErrorContains(t, err2, "skipped 49 bytes; buffer exhausted")
	})
}
