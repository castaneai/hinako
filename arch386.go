package hinako

import (
	"encoding/binary"
	"unsafe"
)

type Arch386 struct{}

func (a *Arch386) DisassembleMode() int {
	return 32
}

func (a *Arch386) NearJumpSize() uint {
	return uint(1 + unsafe.Sizeof(uint32(0)))
}

func (a *Arch386) FarJumpSize() uint {
	return uint(2 + unsafe.Sizeof(uint32(0))*2)
}

func (a *Arch386) NewNearJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.NearJumpSize())
	asm[0] = _ASM_OP_NEAR_JMP
	*(*int32)(unsafe.Pointer(&asm[1])) = int32(to) - int32(from) - int32(a.NearJumpSize())
	return asm
}

func (a *Arch386) NewFarJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.FarJumpSize())
	binary.LittleEndian.PutUint16(asm, _ASM_OP_FAR_JMP)
	binary.LittleEndian.PutUint32(asm[2:], uint32(from+6))
	binary.LittleEndian.PutUint32(asm[6:], uint32(to))
	return asm
}
