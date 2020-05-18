package seccomp

import "testing"

func TestError(t *testing.T) {
	msg := "some error message"
	err := Error(msg)

	if msg != err.Error() {
		t.Errorf("wanted '%s', but got '%s'", msg, err.Error())
	}
}
