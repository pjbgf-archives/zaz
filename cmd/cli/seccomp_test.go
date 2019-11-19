package cli

import (
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestNewSeccompFromGo(t *testing.T) {
	t.Run("valid scenarios", func(t *testing.T) {
		assertThat := func(assumption string, args []string, expected *seccompFromGo) {
			should := should.New(t)
			actual, err := newSeccompFromGo(args)

			should.NotError(err, assumption)
			should.BeEqual(expected, actual, assumption)
		}

		assertThat("should parse filename",
			[]string{"/test/filename"},
			&seccompFromGo{filePath: "/test/filename"})
	})

	t.Run("invalid scenarios", func(t *testing.T) {
		assertThat := func(assumption string, args []string) {
			should := should.New(t)
			_, err := newSeccompFromGo(args)

			should.Error(err, assumption)
		}

		assertThat("should error if no arguments", []string{})
	})
}
