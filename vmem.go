package hinako

type virtualAllocatedMemory struct {
	Addr       uintptr
	Size       uint
	oldProtect uintptr
}

func newVirtualAllocatedMemory(size uint, protectLevel int) (*virtualAllocatedMemory, error) {
	addr, _, err := virtualAlloc.Call(0, uintptr(size), _MEM_COMMIT, uintptr(protectLevel))
	if addr == 0 {
		return nil, err
	}
	return &virtualAllocatedMemory{Addr: addr, Size: size}, nil
}

func (vmem *virtualAllocatedMemory) Read(p []byte) (int, error) {
	err := unsafeReadMemory(vmem.Addr, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (vmem *virtualAllocatedMemory) Write(p []byte) (int, error) {
	err := unsafeWriteMemory(vmem.Addr, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (vmem *virtualAllocatedMemory) WriteAt(p []byte, off int64) (int, error) {
	err := unsafeWriteMemory(vmem.Addr+uintptr(off), p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (vmem *virtualAllocatedMemory) Close() {
	if r, _, err := virtualFree.Call(vmem.Addr, 0, _MEM_RELEASE); r == 0 {
		panic(err)
	}
}
