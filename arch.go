package hinako

import (
	"fmt"
	"runtime"
)

const (
	_ASM_OP_NEAR_JMP = 0xE9       // jmp rel32
	_ASM_OP_FAR_JMP  = 0x25FF     // jmp dword ptr[addr32]
	_ASM_OP_PUSH     = 0x68       // push
	_ASM_OP_MOV_RSP4 = 0x042444C7 // mov DWORD PTR [rsp+0x4], ...
	_ASM_OP_RET      = 0xC3       // ret
)

type arch interface {
	DisassembleMode() int
	NearJumpSize() uint
	FarJumpSize() uint
	NewNearJumpAsm(from, to uintptr) []byte
	NewFarJumpAsm(from, to uintptr) []byte
}

func maxTrampolineSize(arch arch) uint {
	return 40
}

func isFarJump(from, to uintptr) bool {
	if to >= from {
		return (to - from) > uintptr(0x7fff0000)
	} else {
		return (from - to) > uintptr(0x7fff0000)
	}
}

func jumpSize(arch arch, from, to uintptr) uint {
	if isFarJump(from, to) {
		return arch.FarJumpSize()
	}
	return arch.NearJumpSize()
}

func newJumpAsm(arch arch, from, to uintptr) []byte {
	if isFarJump(from, to) {
		return arch.NewFarJumpAsm(from, to)
	}
	return arch.NewNearJumpAsm(from, to)
}

//NewRuntimeArch func
func NewRuntimeArch() (arch, error) {
	switch runtime.GOARCH {
	case "386":
		return &arch386{}, nil
	case "amd64":
		return &archAMD64{}, nil
	}
	return nil, fmt.Errorf("unsupported arch: %s", runtime.GOARCH)
}
