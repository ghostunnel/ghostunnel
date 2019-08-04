package certloader

// Logger interface used to log information
// TODO: this should probably be shared across various ghostunnel packages
type Logger interface {
	Printf(format string, v ...interface{})
}
