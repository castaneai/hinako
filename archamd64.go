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
	return 14
}

func (a *archAMD64) NewNearJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.NearJumpSize())
	asm[0] = _ASM_OP_NEAR_JMP
	*(*int32)(unsafe.Pointer(&asm[1])) = int32(to) - int32(from) - int32(a.NearJumpSize())
	return asm
}

func (a *archAMD64) NewFarJumpAsm(from, to uintptr) []byte {
	asm := make([]byte, a.FarJumpSize())

	// 3) This one was found on Nikolay Igotti’s blog.
	// http://www.ragestorm.net/blogs/?p=107
	asm[0] = _ASM_OP_PUSH
	binary.LittleEndian.PutUint32(asm[1:], lowDword(uint64(to)))
	binary.LittleEndian.PutUint32(asm[5:], _ASM_OP_MOV_RSP4)
	binary.LittleEndian.PutUint32(asm[9:], highDword(uint64(to)))
	asm[13] = _ASM_OP_RET
	return asm
}

func lowDword(qword uint64) uint32 {
	return uint32(qword & 0xffffffff)
}

func highDword(qword uint64) uint32 {
	return uint32(qword >> 32)
}
