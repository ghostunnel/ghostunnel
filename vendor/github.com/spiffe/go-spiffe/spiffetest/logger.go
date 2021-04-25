package spiffetest

import "testing"

type Logger struct {
	tb testing.TB
}

func NewLogger(tb testing.TB) *Logger {
	return &Logger{
		tb: tb,
	}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.tb.Logf("[DEBUG]: "+format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.tb.Logf("[INFO]: "+format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.tb.Logf("[WARN]: "+format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.tb.Logf("[ERROR]: "+format, args...)
}
