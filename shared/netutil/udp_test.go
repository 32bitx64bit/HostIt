package netutil

import (
	"errors"
	"reflect"
	"testing"
)

type fakeUDPBufferSetter struct {
	readErr  error
	writeErr error
	calls    []string
	read     int
	write    int
}

func (f *fakeUDPBufferSetter) SetReadBuffer(bytes int) error {
	f.calls = append(f.calls, "read")
	f.read = bytes
	return f.readErr
}

func (f *fakeUDPBufferSetter) SetWriteBuffer(bytes int) error {
	f.calls = append(f.calls, "write")
	f.write = bytes
	return f.writeErr
}

func TestSetUDPBuffersSuccess(t *testing.T) {
	setter := &fakeUDPBufferSetter{}
	result := SetUDPBuffers(setter, 256*1024, 64*1024)

	if !result.OK() {
		t.Fatalf("SetUDPBuffers result = %+v, want success", result)
	}
	if result.ReadBytes != 256*1024 || result.WriteBytes != 64*1024 {
		t.Fatalf("reported requests = %d/%d, want %d/%d", result.ReadBytes, result.WriteBytes, 256*1024, 64*1024)
	}
	if setter.read != result.ReadBytes || setter.write != result.WriteBytes {
		t.Fatalf("applied requests = %d/%d, want %d/%d", setter.read, setter.write, result.ReadBytes, result.WriteBytes)
	}
	if want := []string{"read", "write"}; !reflect.DeepEqual(setter.calls, want) {
		t.Fatalf("buffer setter calls = %v, want %v", setter.calls, want)
	}
}

func TestSetUDPBuffersReportsErrorsIndependently(t *testing.T) {
	readErr := errors.New("read buffer rejected")
	writeErr := errors.New("write buffer rejected")
	setter := &fakeUDPBufferSetter{readErr: readErr, writeErr: writeErr}

	result := SetUDPBuffers(setter, 1, 2)

	if result.OK() {
		t.Fatal("SetUDPBuffers reported success when both operations failed")
	}
	if !errors.Is(result.ReadErr, readErr) {
		t.Fatalf("read error = %v, want %v", result.ReadErr, readErr)
	}
	if !errors.Is(result.WriteErr, writeErr) {
		t.Fatalf("write error = %v, want %v", result.WriteErr, writeErr)
	}
	if want := []string{"read", "write"}; !reflect.DeepEqual(setter.calls, want) {
		t.Fatalf("buffer setter calls = %v, want %v", setter.calls, want)
	}
}

func TestSetUDPBuffersStillWritesAfterReadFailure(t *testing.T) {
	readErr := errors.New("read buffer rejected")
	setter := &fakeUDPBufferSetter{readErr: readErr}

	result := SetUDPBuffers(setter, 4096, 8192)

	if !errors.Is(result.ReadErr, readErr) || result.WriteErr != nil {
		t.Fatalf("SetUDPBuffers errors = read:%v write:%v", result.ReadErr, result.WriteErr)
	}
	if setter.write != 8192 {
		t.Fatalf("write buffer request = %d, want 8192", setter.write)
	}
}
