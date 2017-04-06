package hinako

import "testing"

func TestCreateHookByName(t *testing.T) {
	CreateHookByName("ws2_32.dll", "send")
}
