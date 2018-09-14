package hinako

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func TestHookArch386(t *testing.T) {
	if runtime.GOARCH != "386" {
		t.Skip()
	}
	if err := testHook(&arch386{}); err != nil {
		t.Fatal(err)
	}
}

func TestHookArchAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip()
	}
	if err := testHook(&archAMD64{}); err != nil {
		t.Fatal(err)
	}
}

func testHook(arch arch) error {
	// Before hook
	// Call MessageBoxW
	target := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	printDisas(arch, target.Addr(), int(maxTrampolineSize(arch)), "original messageboxw")
	target.Call(0, wstrPtr("MessageBoxW"), wstrPtr("MessageBoxW"), 0)

	// API Hooking by hinako
	if err := func() error {
		var originalMessageBoxW *syscall.Proc
		hook, err := NewHookByName(arch, "user32.dll", "MessageBoxW", func(hWnd syscall.Handle, lpText, lpCaption *uint16, uType uint) int {
			printDisas(arch, originalMessageBoxW.Addr(), int(maxTrampolineSize(arch)), "original messageboxw (tramp)")
			r, _, _ := originalMessageBoxW.Call(uintptr(hWnd), wstrPtr("Hooked!"), wstrPtr("Hooked!"), uintptr(uType))
			return int(r)
		})
		if err != nil {
			return err
		}
		defer hook.Close()
		originalMessageBoxW = hook.OriginalProc

		// After hook
		// Call MessageBoxW
		if r, _, err := target.Call(0, wstrPtr("MessageBoxW"), wstrPtr("MessageBoxW"), 0); r == 0 {
			return err
		}
		return nil
	}(); err != nil {
		return err
	}

	// after close hook
	if r, _, err := target.Call(0, wstrPtr("MessageBoxW"), wstrPtr("MessageBoxW"), 0); r == 0 {
		return err
	}
	return nil
}

func wstrPtr(str string) uintptr {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return uintptr(unsafe.Pointer(ptr))
}
