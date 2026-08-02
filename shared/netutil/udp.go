package netutil

const (
	// SharedUDPReadBufferBytes and SharedUDPWriteBufferBytes are the kernel
	// buffers used by the agent/server tunnel UDP sockets.
	SharedUDPReadBufferBytes  = 256 * 1024
	SharedUDPWriteBufferBytes = 256 * 1024
	// RouteUDPReadBufferBytes and RouteUDPWriteBufferBytes are the buffers
	// used by public per-route UDP sockets.
	RouteUDPReadBufferBytes  = 128 * 1024
	RouteUDPWriteBufferBytes = 128 * 1024
)

// UDPBufferSetter is implemented by net.UDPConn. Keeping the narrow interface
// makes socket-buffer setup testable without opening a real socket or depending
// on platform-specific effective buffer sizes.
type UDPBufferSetter interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// UDPBufferResult reports each requested socket-buffer operation separately.
// Operating systems may cap, round, or otherwise adjust these requests; the
// result deliberately reports only whether each request was accepted.
type UDPBufferResult struct {
	ReadBytes  int
	WriteBytes int
	ReadErr    error
	WriteErr   error
}

// OK reports whether both socket-buffer requests succeeded.
func (r UDPBufferResult) OK() bool {
	return r.ReadErr == nil && r.WriteErr == nil
}

// SetUDPBuffers requests independent receive and transmit buffer sizes. Both
// operations are always attempted so a rejected read-buffer request does not
// prevent write-buffer configuration (or vice versa). Callers can log either
// error as a non-fatal diagnostic using the requested sizes in the result.
func SetUDPBuffers(conn UDPBufferSetter, readBytes, writeBytes int) UDPBufferResult {
	result := UDPBufferResult{
		ReadBytes:  readBytes,
		WriteBytes: writeBytes,
	}
	result.ReadErr = conn.SetReadBuffer(readBytes)
	result.WriteErr = conn.SetWriteBuffer(writeBytes)
	return result
}
