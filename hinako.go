package hinako

import (
	"syscall"

	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"strconv"
	"strings"
	"unsafe"
)

import "C"

var (
	kernel32       = syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc   = kernel32.MustFindProc("VirtualAlloc")
	virtualProtect = kernel32.MustFindProc("VirtualProtect")
	oldProtect     uintptr
)

const (
	_PAGE_NOACCESS          = 0x01
	_PAGE_READONLY          = 0x02
	_PAGE_READWRITE         = 0x04
	_PAGE_EXECUTE_READ      = 0x20
	_PAGE_EXECUTE_READWRITE = 0x40

	_MEM_COMMIT  = 0x00001000
	_MEM_RESERVE = 0x00002000
	_MEM_RELEASE = 0x8000
)

type Trampoline struct {
	Addr uintptr
	Size uintptr
}

func NearJumpPatchSize() uintptr {
	return strconv.IntSize + 1
}

func AbsJumpPatchSize() uintptr {
	return unsafe.Sizeof(uintptr(0))*2 + 2
}

// max trampoline size = longest instruction (6) starting 1 byte before jump patch boundary
func MaxTrampolineSize() uintptr {
	return AbsJumpPatchSize() - 1 + 6
}

func CreateHookByName(dllPath, funcName string) error {
	dll, err := syscall.LoadDLL(dllPath)
	if err != nil {
		return err
	}
	proc, err := dll.FindProc(funcName)
	originalFunc := proc.Addr()
	newFunc := uintptr(0) // TODO: nullptr....
	return CreateHook(originalFunc, newFunc)
}

func CreateHook(originalFunc, hookFunc uintptr) error {
	// todo: already hooked?

	// todo: check abs jmp

	// オリジナル関数の先頭20バイトをdisassemble
	funcHeadBytes := unsafeReadMemory(originalFunc, 20)
	insts, err := disassemble(funcHeadBytes)
	if err != nil {
		return err
	}

	minOffset, err := getMinOffset(insts, NearJumpPatchSize())
	if err != nil {
		return err
	}

	// トランポリン取得
	trampoline, err := createTrampoline(MaxTrampolineSize())
	if err != nil {
		return err
	}

	// 元関数の先頭部分をトランポリンに退避
	C.memcpy(trampoline.Addr, originalFunc, minOffset)

	// 元関数の先頭部分を書き換え
	oldProtect = 0
	virtualProtect.Call(originalFunc, MaxTrampolineSize(), _PAGE_EXECUTE_READWRITE, oldProtect)
	return nil
}

// todo: 複数のトランポリン対応
func createTrampoline(size uintptr) (Trampoline, error) {
	addr, _, err := virtualAlloc.Call(0, size, _MEM_COMMIT, _PAGE_READWRITE)
	if err != nil {
		return nil, err
	}
	return Trampoline{Addr: addr, Size: size}, nil
}

func getMinOffset(insts []x86asm.Inst, jumpPatchSize uintptr) (uintptr, error) {
	minOffset := uintptr(0)
	for i := 0; i < len(insts) && i < int(jumpPatchSize); i++ {
		if isBranchInst(insts[i]) {
			return -1, fmt.Errorf("Branch opcode found before jump patch area")
		}
		minOffset += uintptr(insts[i].Len)
	}
	if minOffset < jumpPatchSize {
		return -1, fmt.Errorf("Unable to disassemble enough instructions we fail")
	}
	return minOffset, nil
}

func isBranchInst(inst x86asm.Inst) bool {
	instr := inst.String()
	return strings.HasPrefix(instr, "J") || strings.HasPrefix(instr, "CALL")
}

func disassemble(src []byte) ([]x86asm.Inst, error) {
	r := make([]x86asm.Inst, 0, len(src)/15)

	for len(src) > 0 {
		inst, err := x86asm.Decode(src, 32)
		if err != nil {
			return nil, err
		}
		r = append(r, inst)
		src = src[inst.Len:]
	}
	return r, nil
}

func unsafeReadMemory(ptr uintptr, size uint32) []byte {
	out := make([]byte, size)
	for i := range out {
		addr := (*byte)(unsafe.Pointer(ptr + uintptr(i)))
		out[i] = *addr
	}
	return out
}
