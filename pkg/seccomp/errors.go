package seccomp

// Error defines an error type that can be used as constant.
type Error string

func (e Error) Error() string { return string(e) }

// ErrInvalidProfile is returned when an invalid seccomp profile is provided.
const ErrInvalidProfile = Error("profile content is invalid")

// ErrHighRiskSyscallAllowed is returned when a profile allows high-risk system calls.
const ErrHighRiskSyscallAllowed = Error("profile allows high-risk system calls")
