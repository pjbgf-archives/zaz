# zaz

A command-line tool to assist on assessing container security requirements and generating seccomp profiles.

![GitHub Workflow Status](https://github.com/pjbgf/zaz/workflows/go/badge.svg)
[![codecov](https://codecov.io/gh/pjbgf/zaz/branch/master/graph/badge.svg?token=pb1nLayr67)](https://codecov.io/gh/pjbgf/zaz)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=pjbgf/zaz)](https://dependabot.com)
[![GoReport](https://goreportcard.com/badge/github.com/pjbgf/zaz)](https://goreportcard.com/report/github.com/pjbgf/zaz)
[![GoDoc](https://godoc.org/github.com/pjbgf/zaz?status.svg)](https://godoc.org/github.com/pjbgf/zaz)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)


## zaz seccomp

This module focuses on the generation and validation of seccomp profiles.

### zaz seccomp docker

Generate seccomp profiles based on executing a command on a docker image. 
This command "brute forces" the profile generation by trying to remove all possible 
syscalls, then consolidating all syscalls the command cannot be executed without.

```sh
zaz seccomp docker IMAGE COMMAND 

# Calculates seccomp profile for a ping command inside an alpine image:
zaz seccomp docker alpine "ping -c5 8.8.8.8"
```


### zaz seccomp application-binary

Generates seccomp profiles from the executable of an application. 
Note that on top of the application needs, some container images may add additional syscalls.


```sh
zaz seccomp BINARY_PATH

# Calculates seccomp profile from an application binary
zaz seccomp bin/webapi
```
*Currently only golang binaries are supported.*

### zaz seccomp zaz seccomp --log-file=/var/log/syslog 423

Generates seccomp profiles by assessing the kernels logs for a given process ID

```sh
# Setting the syslog path (default is "/var/log/kern.log"):
To get a profile based on process id 4325:

zaz seccomp --log-file=/var/log/syslog 4325
```

### zaz seccomp verify path/profile.json

Validates a seccomp profile, returning a list of high-risk system calls being allowed.
```sh
zaz seccomp verify no-highrisk-profile.json
```


## License

Licensed under the MIT License. You may obtain a copy of the License [here](LICENSE).