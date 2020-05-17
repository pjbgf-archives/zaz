package seccomp

func NewProfileVerifier() *ProfileVerifier {
	return &ProfileVerifier{}
}

type ProfileVerifier struct {
}

type Warning struct {
	SyscallName string
}

func (v *ProfileVerifier) Run() ([]Warning, error) {
	return []Warning{}, nil
}
