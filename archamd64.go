package hinako

import (
	"encoding/binary"
	"unsafe"
)

type archAMD64 struct{}

func (a *archAMD64) DisassembleMode() int {
	return 64
}

func (a *archAMD64) NearJumpSize() uint {
	return uint(1 + unsafe.Sizeof(uint32(0)))
}

func (a *archAMD64) FarJumpSize() uint {
	return 12
}

func (a *archAMD64) NewNearJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.NearJumpSize())
	asm[0] = _ASM_OP_NEAR_JMP
	*(*int32)(unsafe.Pointer(&asm[1])) = int32(to) - int32(from) - int32(a.NearJumpSize())
	return asm
}

func (a *archAMD64) NewFarJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.FarJumpSize())
	binary.LittleEndian.PutUint16(asm, _ASM_OP_AMD64_MOVABS_RAX)
	binary.LittleEndian.PutUint64(asm[2:], uint64(to))
	binary.LittleEndian.PutUint16(asm[10:], _ASM_OP_AMD64_JMP_RAX)
	return asm
}
