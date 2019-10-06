package spiffe

// Logger is a logging interface used to log information
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type nullLogger struct{}

func (nullLogger) Debugf(format string, args ...interface{}) {}
func (nullLogger) Infof(format string, args ...interface{})  {}
func (nullLogger) Warnf(format string, args ...interface{})  {}
func (nullLogger) Errorf(format string, args ...interface{}) {}
