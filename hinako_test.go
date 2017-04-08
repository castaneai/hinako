package hinako

import (
	"reflect"
	"syscall"
	"testing"
	"unsafe"
)

func TestIA32Arch_NewNearJumpAsm(t *testing.T) {
	ia32 := IA32Arch{}
	asm := ia32.NewNearJumpAsm(uintptr(100), uintptr(150))
	expect := []byte{0xE9, 45, 0, 0, 0}
	if !reflect.DeepEqual(asm, expect) {
		t.Errorf("%v != %v", asm, expect)
	}
}

func TestIA32Arch_NewFarJumpAsm(t *testing.T) {
	ia32 := IA32Arch{}
	asm := ia32.NewFarJumpAsm(uintptr(0), uintptr(0x12345678))
	expect := []byte{0xFF, 0x25, 0x06, 0, 0, 0, 0x78, 0x56, 0x34, 0x12}
	if !reflect.DeepEqual(asm, expect) {
		t.Errorf("%v != %v", asm, expect)
	}
}

func TestNewVirtualAllocatedMemory(t *testing.T) {
	vmem, err := NewVirtualAllocatedMemory(64, syscall.PAGE_EXECUTE_READWRITE)
	if err != nil {
		t.Errorf(err.Error())
	}
	defer vmem.Close()
}

func TestVirtualAllocatedMemory_ReadWrite(t *testing.T) {
	vmem, err := NewVirtualAllocatedMemory(64, syscall.PAGE_EXECUTE_READWRITE)
	if err != nil {
		t.Errorf(err.Error())
	}
	w := []byte("Hello, hinako")
	vmem.Write(w)

	r := make([]byte, len(w))
	vmem.Read(r)
	if !reflect.DeepEqual(r, w) {
		t.Errorf("%v != %v", r, w)
	}
	defer vmem.Close()
}

func toLPCWSTR(str string) uintptr {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return uintptr(unsafe.Pointer(ptr))
}

func TestNewHookByName(t *testing.T) {
	targetFunc := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	targetFunc.Call(0, toLPCWSTR("MessageBoxW"), toLPCWSTR("MessageBoxW"), 0)

	var originalProc *syscall.Proc

	arch := IA32Arch{}
	dll := syscall.MustLoadDLL("user32.dll")
	targetProc := dll.MustFindProc("MessageBoxW")

	hookFunc := syscall.NewCallback(func(a, b, c, d uintptr) uintptr {
		r, _, _ := originalProc.Call(0, toLPCWSTR("hooked MessageBoxW"), toLPCWSTR("hooked MessageBoxW"), 0)
		return r
	})

	hook, err := NewHook(&arch, targetProc, hookFunc)
	if err != nil {
		t.Errorf(err.Error())
	}
	originalProc = &syscall.Proc{Dll: dll, Name: "MessageBoxW"}
	val := reflect.Indirect(reflect.ValueOf(originalProc))
	*(*uintptr)(unsafe.Pointer(val.FieldByName("addr").UnsafeAddr())) = hook.originalFunc

	targetFunc.Call(1, toLPCWSTR("target function"), toLPCWSTR("target function"), 2)
}
