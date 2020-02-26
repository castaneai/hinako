package hinako

import (
	"reflect"
	"testing"
)

func TestArch386_NewNearJumpAsm(t *testing.T) {
	ia32 := Arch386{}
	asm := ia32.NewNearJumpAsm(uintptr(100), uintptr(150))
	expect := []byte{0xE9, 45, 0, 0, 0}
	if !reflect.DeepEqual(asm, expect) {
		t.Errorf("%v != %v", asm, expect)
	}
}

func TestArch386_NewFarJumpAsm(t *testing.T) {
	ia32 := Arch386{}
	asm := ia32.NewFarJumpAsm(uintptr(0), uintptr(0x12345678))
	expect := []byte{0xFF, 0x25, 0x06, 0, 0, 0, 0x78, 0x56, 0x34, 0x12}
	if !reflect.DeepEqual(asm, expect) {
		t.Errorf("%v != %v", asm, expect)
	}
}
