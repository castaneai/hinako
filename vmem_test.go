package hinako

import (
	"reflect"
	"syscall"
	"testing"
)

func TestNewVirtualAllocatedMemory(t *testing.T) {
	vmem, err := newVirtualAllocatedMemory(64, syscall.PAGE_EXECUTE_READWRITE)
	if err != nil {
		t.Errorf(err.Error())
	}
	defer vmem.Close()
}

func TestVirtualAllocatedMemory_ReadWrite(t *testing.T) {
	vmem, err := newVirtualAllocatedMemory(64, syscall.PAGE_EXECUTE_READWRITE)
	if err != nil {
		t.Errorf(err.Error())
	}
	defer vmem.Close()
	w := []byte("Hello, hinako")
	vmem.Write(w)

	r := make([]byte, len(w))
	vmem.Read(r)
	if !reflect.DeepEqual(r, w) {
		t.Errorf("%v != %v", r, w)
	}
}
