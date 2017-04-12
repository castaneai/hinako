hinako
==========
![](http://blog.otaku-streamers.com/wp-content/uploads/2016/11/b551fd2c1d9f9e87861ca65d_1480138863.png)

Windows API hooking (x86) with golang based on [trampoline function](http://jbremer.org/x86-api-hooking-demystified/#ah-trampoline).

## Requirements

- Windows OS
- Golang i386 (**not amd64**)

## Getting Started
Hook [MessageBoxW](https://msdn.microsoft.com/en-us/library/windows/desktop/ms645505(v=vs.85).aspx) Sample

```go
package main

import (
	"fmt"
	"github.com/castaneai/hinako"
	"syscall"
	"unsafe"
)

func main() {
	target := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")

	// Before hook
	// Call MessageBoxW
	target.Call(0, WSTRPtr("MessageBoxW"), WSTRPtr("MessageBoxW"), 0)

	// API Hooking by hinako
	arch := hinako.IA32Arch{}
	var originalMessageBoxW *syscall.Proc = nil
	hook, err := hinako.NewHookByName(&arch, "user32.dll", "MessageBoxW", func(hWnd syscall.Handle, lpText, lpCaption *uint16, uType uint) int {
		r, _, _ := originalMessageBoxW.Call(uintptr(hWnd), WSTRPtr("Hooked!"), WSTRPtr("Hooked!"), uintptr(uType))
		return int(r)
	})
	if err != nil {
		fmt.Printf("hook failed: %s", err.Error())
	}
	originalMessageBoxW = hook.OriginalProc
	defer hook.Close()

	// After hook
	// Call MessageBoxW
	target.Call(0, WSTRPtr("MessageBoxW"), WSTRPtr("MessageBoxW"), 0)
}

func WSTRPtr(str string) uintptr {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return uintptr(unsafe.Pointer(ptr))
}

```


## Test

```
$ go test
```

## Author
[castaneai](http://castaneai.net)
