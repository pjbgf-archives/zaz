package seccomp

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// ProfileVerifier holds the logic for validating seccomp profiles.
type ProfileVerifier struct {
	profileReader io.Reader
}

// NewProfileVerifier initialises and returns a new ProfileVerifier.
func NewProfileVerifier(profileReader io.Reader) *ProfileVerifier {
	return &ProfileVerifier{profileReader}
}

// Warning represents a warning about a system call.
type Warning struct {
	SyscallName string
}

func (v *ProfileVerifier) getProfile() (*specs.LinuxSeccomp, error) {
	content, err := ioutil.ReadAll(v.profileReader)
	if err != nil {
		return nil, ErrInvalidProfile
	}

	var profile specs.LinuxSeccomp
	if err := json.Unmarshal([]byte(content), &profile); err != nil {
		return nil, ErrInvalidProfile
	}

	return &profile, nil
}

// Run executes a seccomp profile validation, returning an error and a list
// of Warning with the high-risk system calls found.
func (v *ProfileVerifier) Run() ([]Warning, error) {
	profile, err := v.getProfile()
	if err != nil {
		return nil, err
	}

	highRiskAllowed := make([]Warning, 0)
	if profile.DefaultAction == specs.ActAllow || profile.DefaultAction == specs.ActLog {
		if len(profile.Syscalls) == 0 {
			for name := range highRiskSystemCalls {
				highRiskAllowed = append(highRiskAllowed, Warning{SyscallName: name})
			}
		} else {
			allowed := make(map[string]bool, len(highRiskSystemCalls))
			for k, v := range highRiskSystemCalls {
				allowed[k] = v
			}
			for _, c := range profile.Syscalls {
				if c.Action == specs.ActErrno || c.Action == specs.ActKill || c.Action == specs.ActTrap {
					for _, name := range c.Names {
						allowed[name] = false
					}
				}
			}
			for name, callAllowed := range allowed {
				if callAllowed {
					highRiskAllowed = append(highRiskAllowed, Warning{SyscallName: name})
				}
			}
		}
	}

	for _, c := range profile.Syscalls {
		if c.Action == specs.ActAllow || c.Action == specs.ActLog {
			for _, name := range c.Names {
				if _, found := highRiskSystemCalls[name]; found {
					highRiskAllowed = append(highRiskAllowed, Warning{SyscallName: name})
				}
			}
		}
	}

	if len(highRiskAllowed) > 0 {
		err = ErrHighRiskSyscallAllowed
	}

	return highRiskAllowed, err
}
