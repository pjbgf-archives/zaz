package seccomp

// Error defines an error type that can be used as constant.
type Error string

// Error returns the error message.
func (e Error) Error() string { return string(e) }

// ErrInvalidProfile is returned when an invalid seccomp profile is provided.
const ErrInvalidProfile = Error("profile content is invalid")

// ErrHighRiskSyscallAllowed is returned when a profile allows high-risk system calls.
const ErrHighRiskSyscallAllowed = Error("profile allows high-risk system calls")

// ErrImageCouldNotBePulled is returned when the image is not found locally and
// cannot be downloaded from an external container registry.
const ErrImageCouldNotBePulled = Error("image could not be pulled")

// ErrCannotFetchContainerStatus is returned when a container cannot have its status
// verified.
const ErrCannotFetchContainerStatus = Error("error trying to fetch container status")

// ErrContainerExecutionTimeout is returned when a container execution times out.
const ErrContainerExecutionTimeout = Error("container execution timed-out")

// ErrContainerExecutionFailure is returned when a container execution fails.
const ErrContainerExecutionFailure = Error("error running container")

// ErrInvalidTemplateName is returned when a invalid template name is used.
const ErrInvalidTemplateName = Error("invalid template name")

// ErrInvalidSyntax is returned when an invalid syntax is used.
const ErrInvalidSyntax = Error("invalid syntax")
