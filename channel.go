package gomavlib

import (
	"context"
	"crypto/rand"
	"errors"
	"io"

	"github.com/bluenviron/gomavlib/v4/pkg/frame"
	"github.com/bluenviron/gomavlib/v4/pkg/message"
	"github.com/bluenviron/gomavlib/v4/pkg/streamwriter"
)

const (
	writeBufferSize = 64
	// A datagram carries any number of frames and a UDP payload can reach
	// 65507 bytes. Reading less than the whole datagram truncates it: the
	// remainder is dropped by the operating system rather than kept for the
	// next read.
	datagramReadBufferSize = 65536
)

type datagramReader struct {
	r    io.ReadCloser
	dump *streamDump
	buf  []byte
	pos  int
}

func (r *datagramReader) readPacket() error {
	if cap(r.buf) < datagramReadBufferSize {
		r.buf = make([]byte, datagramReadBufferSize)
	}

	n, err := r.r.Read(r.buf[:datagramReadBufferSize])
	if n == 0 && err != nil {
		return err
	}

	r.buf = r.buf[:n]
	r.pos = 0

	// The datagram is whole here and its boundary is known, which is exactly
	// what a byte-stream reader loses further down. Recording it costs nothing
	// unless dumping was asked for.
	r.dump.add(r.buf)

	return nil
}

// Read implements io.Reader on top of a datagram transport.
//
// Datagram boundaries do not coincide with frame boundaries: ArduPilot flushes
// whatever contiguous region its UART ring buffer holds, so a frame is cut in
// two whenever the ring wraps. The reader therefore has to behave like a byte
// stream and fetch the next datagram to complete a frame started in the
// previous one, the way pymavlink appends every datagram to one parse buffer.
func (r *datagramReader) Read(p []byte) (int, error) {
	for r.pos >= len(r.buf) {
		err := r.readPacket()
		if err != nil {
			return 0, err
		}
	}

	n := copy(p, r.buf[r.pos:])
	r.pos += n

	return n, nil
}

type readWriter struct {
	io.Reader
	io.Writer
}

func randomByte() (byte, error) {
	var buf [1]byte
	_, err := rand.Read(buf[:])
	return buf[0], err
}

// Channel is a communication channel created by an Endpoint.
// An Endpoint can create channels.
// For instance, a TCP client endpoint creates a single channel, while a TCP
// server endpoint creates a channel for each incoming connection.
type Channel struct {
	node       *Node
	endpoint   Endpoint
	label      string
	rwc        io.ReadWriteCloser
	isDatagram bool

	datagramReader  *datagramReader
	ctx             context.Context
	ctxCancel       func()
	frameReadWriter *frame.ReadWriter
	streamWriter    *streamwriter.Writer
	running         bool

	// in
	chWrite chan any

	// out
	done chan struct{}
}

func (ch *Channel) initialize() error {
	linkID, err := randomByte()
	if err != nil {
		return err
	}

	var rw io.ReadWriter
	if ch.isDatagram {
		var dump *streamDump
		dump, err = newStreamDump(ch.label)
		if err != nil {
			return err
		}

		ch.datagramReader = &datagramReader{r: ch.rwc, dump: dump}
		rw = &readWriter{
			Reader: ch.datagramReader,
			Writer: ch.rwc,
		}
	} else {
		rw = ch.rwc
	}

	ch.frameReadWriter = &frame.ReadWriter{
		ByteReadWriter: rw,
		DialectRW:      ch.node.dialectRW,
		InKey:          ch.node.InKey,
	}
	err = ch.frameReadWriter.Initialize()
	if err != nil {
		return err
	}

	ch.streamWriter = &streamwriter.Writer{
		FrameWriter: ch.frameReadWriter.Writer,
		SystemID:    ch.node.OutSystemID,
		Version: func() streamwriter.Version {
			if ch.node.OutVersion == V2 {
				return streamwriter.V2
			}
			return streamwriter.V1
		}(),
		ComponentID:     ch.node.OutComponentID,
		SignatureLinkID: linkID,
		Key:             ch.node.OutKey,
	}
	err = ch.streamWriter.Initialize()
	if err != nil {
		return err
	}

	ch.ctx, ch.ctxCancel = context.WithCancel(context.Background())
	ch.chWrite = make(chan any, writeBufferSize)
	ch.done = make(chan struct{})

	return nil
}

func (ch *Channel) close() {
	ch.ctxCancel()
	if !ch.running {
		ch.rwc.Close()
		// run() closes the dump for a channel that started; this covers the
		// one that never did.
		if ch.datagramReader != nil {
			ch.datagramReader.dump.close()
		}
	}
}

func (ch *Channel) start() {
	ch.running = true
	ch.node.wg.Add(1)
	go ch.run()
}

func (ch *Channel) run() {
	defer close(ch.done)
	defer ch.node.wg.Done()

	readerDone := make(chan error)
	go func() {
		readerDone <- ch.runReader()
	}()

	writerTerminate := make(chan struct{})
	writerDone := make(chan error)
	go func() {
		writerDone <- ch.runWriter(writerTerminate)
	}()

	var err error

	select {
	case err = <-readerDone:
		ch.rwc.Close()

		close(writerTerminate)
		<-writerDone

	case err = <-writerDone:
		ch.rwc.Close()
		<-readerDone

	case <-ch.ctx.Done():
		close(writerTerminate)
		<-writerDone

		ch.rwc.Close()
		<-readerDone
	}

	ch.ctxCancel()

	if ch.datagramReader != nil {
		ch.datagramReader.dump.close()
	}

	ch.node.pushEvent(&EventChannelClose{
		Channel: ch,
		Error:   err,
	})
	ch.node.closeChannel(ch)
}

func (ch *Channel) runReader() error {
	// wait client here, in order to allow the writer goroutine to start
	// and allow clients to write messages before starting listening to events
	ch.node.pushEvent(&EventChannelOpen{ch})

	for {
		// Datagram and stream transports share this path: datagramReader turns
		// packets into a byte stream, so a parse error is recovered identically
		// in both cases by resynchronising on the next magic byte.
		fr, err := ch.frameReadWriter.Read()
		if err != nil {
			var eerr frame.ReadError
			if errors.As(err, &eerr) {
				ch.node.pushEvent(&EventParseError{err, ch})
				continue
			}
			return err
		}

		evt := &EventFrame{fr, ch}

		if ch.node.nodeStreamRequest != nil {
			ch.node.nodeStreamRequest.onEventFrame(evt)
		}

		ch.node.pushEvent(evt)
	}
}

func (ch *Channel) runWriter(writerTerminate chan struct{}) error {
	for {
		select {
		case what := <-ch.chWrite:
			switch wh := what.(type) {
			case message.Message:
				err := ch.streamWriter.Write(wh)
				if err != nil {
					return err
				}

			case frame.Frame:
				err := ch.frameReadWriter.Write(wh)
				if err != nil {
					return err
				}
			}

		case <-writerTerminate:
			return nil
		}
	}
}

// String implements fmt.Stringer.
func (ch *Channel) String() string {
	return ch.label
}

// Endpoint returns the channel Endpoint.
func (ch *Channel) Endpoint() Endpoint {
	return ch.endpoint
}

func (ch *Channel) write(what any) {
	select {
	case ch.chWrite <- what:
	case <-ch.ctx.Done():
	default: // buffer is full
	}
}
