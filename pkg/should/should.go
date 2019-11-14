// Package should provide methods for testing go applications.
package should

import (
	"reflect"
	"runtime"
	"testing"
)

// Should define easy to use methods for testing go applications.
type Should struct {
	t *testing.T
}

// New initialises a new Should instance.
func New(t *testing.T) *Should {
	return &Should{t}
}

// BeNil fails the test if value is not nil.
func (s *Should) BeNil(value interface{}, assumption string) {
	if value != nil {
		s.t.Log(assumption)

		_, file, line, ok := runtime.Caller(1)
		if ok {
			s.t.Logf("%s:%d", file, line)
		}

		s.t.Error("should not be nil")
	}
}

// Error fails the test if err is nil.
func (s *Should) Error(err error, assumption string) {
	if err == nil {
		s.t.Log(assumption)

		_, file, line, ok := runtime.Caller(1)
		if ok {
			s.t.Logf("%s:%d", file, line)
		}

		s.t.Error("error is nil")
	}
}

// NotError fails the test if err is not nil.
func (s *Should) NotError(err error, assumption string) {
	if err != nil {
		s.t.Log(assumption)

		_, file, line, ok := runtime.Caller(1)
		if ok {
			s.t.Logf("%s:%d", file, line)
		}

		s.t.Error("error not nil")
	}
}

// BeEqual compares the values of both expected and actual and fails the test if they differ.
func (s *Should) BeEqual(expected, actual interface{}, assumption string) {
	if !reflect.DeepEqual(expected, actual) {
		s.t.Log(assumption)

		_, file, line, ok := runtime.Caller(1)
		if ok {
			s.t.Logf("%s:%d", file, line)
		}

		s.t.Errorf("expected '%s' but got '%s' instead", expected, actual)
	}
}

// HaveSameType compares the types of both expected and actual and fails the test if they differ.
func (s *Should) HaveSameType(expected, actual interface{}, assumption string) {
	expectedType := reflect.TypeOf(expected)
	actualType := reflect.TypeOf(actual)

	if expectedType != actualType {
		s.t.Log(assumption)

		_, file, line, ok := runtime.Caller(1)
		if ok {
			s.t.Logf("%s:%d", file, line)
		}

		s.t.Errorf("expected type '%s' but got '%s' instead", expectedType, actualType)
	}
}
