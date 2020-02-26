package main

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/castaneai/hinako"
)

func main() {
	// Before hook
	// Call MessageBoxW
	target := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	if r, _, err := target.Call(0, wstrPtr("MessageBoxW"), wstrPtr("MessageBoxW"), 0); r == 0 && err != nil {
		log.Fatalf("failed to call MessageBoxW: %+v", err)
	}

	// API Hooking by hinako
	arch := &hinako.Arch386{}
	var originalMessageBoxW *syscall.Proc
	hook, err := hinako.NewHookByName(arch, "user32.dll", "MessageBoxW", func(hWnd syscall.Handle, lpText, lpCaption *uint16, uType uint) int {
		r, _, _ := originalMessageBoxW.Call(uintptr(hWnd), wstrPtr("Hooked!"), wstrPtr("Hooked!"), uintptr(uType))
		return int(r)
	})
	if err != nil {
		log.Fatalf("failed to hook MessageBoxW: %+v", err)
	}
	defer hook.Close()
	originalMessageBoxW = hook.OriginalProc

	// After hook
	// Call MessageBoxW
	if r, _, err := target.Call(0, wstrPtr("MessageBoxW"), wstrPtr("MessageBoxW"), 0); r == 0 && err != nil {
		log.Fatalf("failed to call hooked MessageBoxW: %+v", err)
	}
}

func wstrPtr(str string) uintptr {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return uintptr(unsafe.Pointer(ptr))
}
