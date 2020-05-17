## zaz

A command line tool to automatically generate seccomp profiles.

[![codecov](https://codecov.io/gh/pjbgf/zaz/branch/master/graph/badge.svg?token=pb1nLayr67)](https://codecov.io/gh/pjbgf/zaz)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=pjbgf/zaz)](https://dependabot.com)
[![GoReport](https://goreportcard.com/badge/github.com/pjbgf/zaz)](https://goreportcard.com/report/github.com/pjbgf/zaz)
[![GoDoc](https://godoc.org/github.com/pjbgf/zaz?status.svg)](https://godoc.org/github.com/pjbgf/zaz)
![build](https://github.com/pjbgf/zaz/workflows/go/badge.svg)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)
## zaz seccomp docker

Generate seccomp profiles based on executing a command on a docker image. 
This command "brute forces" the profile generation by trying to remove all possible 
syscalls, then consolidating all syscalls the command cannot be executed without.

```
zaz seccomp docker IMAGE COMMAND 

# Calculates seccomp profile for a ping command inside an alpine image:
zaz seccomp docker alpine "ping -c5 8.8.8.8"
```


## License

Licensed under the MIT License. You may obtain a copy of the License [here](LICENSE).