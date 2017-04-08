package hinako

import (
	"syscall"

	"encoding/binary"
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"strings"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc          = kernel32.NewProc("VirtualAlloc")
	virtualFree           = kernel32.NewProc("VirtualFree")
	virtualProtect        = kernel32.NewProc("VirtualProtect")
	flushInstructionCache = kernel32.NewProc("FlushInstructionCache")
)

const (
	_MEM_COMMIT      = 0x00001000
	_MEM_RELEASE     = 0x8000
	_ASM_OP_NEAR_JMP = 0xE9   // jmp rel32
	_ASM_OP_FAR_JMP  = 0x25FF // jmp dword ptr[addr32]
)

type VirtualAllocatedMemory struct {
	Addr       uintptr
	Size       uint
	oldProtect uintptr
}

func changeMemoryProtectLevel(ptr uintptr, size, protectLevel int) (int, error) {
	oldProtectLevel := 0
	r, _, err := virtualProtect.Call(ptr, uintptr(size), uintptr(protectLevel), uintptr(unsafe.Pointer(&oldProtectLevel)))
	if r == 0 {
		return -1, err
	}
	return oldProtectLevel, nil
}

func unsafeReadMemory(ptr uintptr, out []byte) error {
	for i := range out {
		out[i] = *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
	}
	// todo: error handling
	return nil
}

func unsafeWriteMemory(ptr uintptr, in []byte) error {
	for i, b := range in {
		*(*byte)(unsafe.Pointer(ptr + uintptr(i))) = b
	}
	// todo: error handling
	return nil
}

func NewVirtualAllocatedMemory(size uint, protectLevel int) (*VirtualAllocatedMemory, error) {
	addr, _, err := virtualAlloc.Call(0, uintptr(size), _MEM_COMMIT, uintptr(protectLevel))
	if addr == 0 {
		return nil, err
	}
	return &VirtualAllocatedMemory{Addr: addr, Size: size}, nil
}

func (vmem *VirtualAllocatedMemory) Read(p []byte) (int, error) {
	err := unsafeReadMemory(vmem.Addr, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (vmem *VirtualAllocatedMemory) Write(p []byte) (int, error) {
	err := unsafeWriteMemory(vmem.Addr, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (vmem *VirtualAllocatedMemory) WriteAt(p []byte, off int64) (int, error) {
	err := unsafeWriteMemory(vmem.Addr+uintptr(off), p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (vmem *VirtualAllocatedMemory) Close() error {
	r, _, err := virtualFree.Call(vmem.Addr, 0, _MEM_RELEASE)
	if r == 0 {
		return err
	}
	return nil
}

func (vmem *VirtualAllocatedMemory) RestoreOriginalProtect() error {
	dummy := uintptr(0)
	r, _, err := virtualProtect.Call(vmem.Addr, uintptr(vmem.Size), vmem.oldProtect, uintptr(unsafe.Pointer(&dummy)))
	if r == 0 || err != nil {
		return err
	}
	return nil
}

func (vmem *VirtualAllocatedMemory) SetProtectToExecutable() error {
	vmem.oldProtect = uintptr(0)
	r, _, err := virtualProtect.Call(vmem.Addr, uintptr(vmem.Size), syscall.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&(vmem.oldProtect))))
	if r == 0 {
		return err
	}
	return nil
}

type Arch interface {
	MaxTrampolineSize() uint

	IsFarJump(from, to uintptr) bool
	JumpSize(from, to uintptr) uint
	NearJumpSize() uint
	FarJumpSize() uint

	NewJumpAsm(from, to uintptr) []byte
	NewNearJumpAsm(from, to uintptr) []byte
	NewFarJumpAsm(from, to uintptr) []byte
}

type arch struct{}

type IA32Arch struct{}

func (a *IA32Arch) MaxTrampolineSize() uint {
	// todo: why??
	return a.FarJumpSize() - 1 + 6
}

func (a *IA32Arch) IsFarJump(from, to uintptr) bool {
	if to >= from {
		return (to - from) > uintptr(0x7fff0000)
	} else {
		return (from - to) > uintptr(0x7fff0000)
	}
}

func (a *IA32Arch) JumpSize(from, to uintptr) uint {
	if a.IsFarJump(from, to) {
		return a.FarJumpSize()
	}
	return a.NearJumpSize()
}

func (a *IA32Arch) NearJumpSize() uint {
	return uint(1 + unsafe.Sizeof(uint32(0)))
}

func (a *IA32Arch) FarJumpSize() uint {
	return uint(2 + unsafe.Sizeof(uint32(0))*2)
}

func (a *IA32Arch) NewJumpAsm(from, to uintptr) []byte {
	if a.IsFarJump(from, to) {
		return a.NewFarJumpAsm(from, to)
	}
	return a.NewNearJumpAsm(from, to)
}

func (a *IA32Arch) NewNearJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.NearJumpSize())
	asm[0] = _ASM_OP_NEAR_JMP
	*(*int32)(unsafe.Pointer(&asm[1])) = int32(to) - int32(from) - int32(a.NearJumpSize())
	return asm
}

func (a *IA32Arch) NewFarJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.FarJumpSize())
	binary.LittleEndian.PutUint16(asm, _ASM_OP_FAR_JMP)
	binary.LittleEndian.PutUint32(asm[2:], uint32(from+6))
	binary.LittleEndian.PutUint32(asm[6:], uint32(to))
	return asm
}

type Hook struct {
	trampoline   *VirtualAllocatedMemory
	patchSize    int
	originalFunc uintptr
	hookFunc     uintptr
}

func (h *Hook) Close() {
	if h.trampoline == nil {
		return
	}
	patch := make([]byte, h.patchSize)
	err := unsafeReadMemory(h.trampoline.Addr, patch)
	if err != nil {
		panic(err)
	}
	err = unsafeWriteMemory(h.originalFunc, patch)
	if err != nil {
		panic(err)
	}
	err = h.trampoline.RestoreOriginalProtect()
	if err != nil {
		panic(err)
	}
	defer h.trampoline.Close()
}

func NewHook(arch Arch, targetProc *syscall.Proc, hookFunc uintptr) (*Hook, error) {
	// todo: already hooked?
	originalFunc := targetProc.Addr()

	originalFuncHead := make([]byte, 20)
	err := unsafeReadMemory(originalFunc, originalFuncHead)
	if err != nil {
		return nil, err
	}

	insts, err := disassemble(originalFuncHead)
	if err != nil {
		return nil, err
	}

	jumpSize := arch.JumpSize(originalFunc, hookFunc)
	patchSize, err := getAsmPatchSize(insts, jumpSize)
	if err != nil {
		return nil, err
	}

	// トランポリン領域の作成（実行可能領域）
	tramp, err := NewVirtualAllocatedMemory(arch.MaxTrampolineSize(), syscall.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, err
	}

	// 元関数のpatch部分をトランポリンに退避
	_, err = tramp.Write(originalFuncHead[:patchSize])
	if err != nil {
		return nil, err
	}

	// トランポリンに元関数へのjumpを追加
	jmp := arch.NewJumpAsm(tramp.Addr+uintptr(patchSize), originalFunc+uintptr(patchSize))

	_, err = tramp.WriteAt(jmp, int64(patchSize))
	if err != nil {
		return nil, err
	}

	// 元関数のパッチ領域を書き込み可能にする
	oldProtect, err := changeMemoryProtectLevel(originalFunc, int(arch.MaxTrampolineSize()), syscall.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, err
	}

	// 元関数の先頭をフック関数へのjumpに書き換え（フック作動開始！）
	hookJmp := arch.NewJumpAsm(originalFunc, hookFunc)
	err = unsafeWriteMemory(originalFunc, hookJmp)
	if err != nil {
		return nil, err
	}

	// 書き込み可能にしたのを戻す
	_, err = changeMemoryProtectLevel(originalFunc, int(arch.MaxTrampolineSize()), oldProtect)
	if err != nil {
		return nil, err
	}

	// clear inst cache
	currentProcessHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	flushInstructionCache.Call(uintptr(currentProcessHandle), tramp.Addr, uintptr(arch.MaxTrampolineSize()))
	flushInstructionCache.Call(uintptr(currentProcessHandle), originalFunc, uintptr(patchSize))

	return &Hook{trampoline: tramp, originalFunc: tramp.Addr, hookFunc: hookFunc, patchSize: patchSize}, nil
}

func getAsmPatchSize(insts []x86asm.Inst, jumpSize uint) (int, error) {
	res := 0
	for i := 0; res < int(jumpSize) && i < len(insts); i++ {
		if isBranchInst(insts[i]) {
			return -1, fmt.Errorf("Branch opcode found before jump patch area")
		}
		res += insts[i].Len
	}
	if res < int(jumpSize) {
		return -1, fmt.Errorf("Unable to insert jmp within patch size")
	}
	return res, nil
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

// ------------ for debug

func printDisas(ptr uintptr, size int, title string) {
	code := make([]byte, size)
	unsafeReadMemory(ptr, code)
	printCodes(code, fmt.Sprintf("[0x%x]", ptr)+title, ptr)
}

func printCodes(code []byte, title string, baseAddr uintptr) {
	insts, _ := disassemble(code)
	printInsts(insts, title, baseAddr)
}

func printInsts(insts []x86asm.Inst, title string, baseAddr uintptr) {
	fmt.Printf("============ %s ==============\n", title)
	addr := baseAddr
	for _, inst := range insts {
		fmt.Printf("[0x%x]%s\n", addr, x86asm.IntelSyntax(inst))
		addr += uintptr(inst.Len)
	}
	fmt.Printf("===========================================\n")
}
