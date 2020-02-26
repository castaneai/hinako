package hinako

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

func printDisas(arch Arch, ptr uintptr, size int, title string) {
	code := make([]byte, size)
	unsafeReadMemory(ptr, code)
	printCodes(arch, code, fmt.Sprintf("[0x%X] %s", ptr, title), ptr)
}

func printCodes(arch Arch, code []byte, title string, baseAddr uintptr) {
	insts, _ := disassemble(code, arch.DisassembleMode())
	printInsts(insts, title, baseAddr)
}

func printInsts(insts []*x86asm.Inst, title string, baseAddr uintptr) {
	fmt.Printf("============ %s ==============\n", title)
	addr := baseAddr
	for _, inst := range insts {
		fmt.Printf("[0x%X] %s\n", addr, x86asm.IntelSyntax(*inst, 0, nil))
		addr += uintptr(inst.Len)
	}
	fmt.Printf("===========================================\n")
}
