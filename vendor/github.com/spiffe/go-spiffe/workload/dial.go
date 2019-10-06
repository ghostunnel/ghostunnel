package workload

import (
	"context"
	"errors"

	"google.golang.org/grpc"
)

type dialConfig struct {
	addr string
	opts []grpc.DialOption
}

type DialOption func(*dialConfig)

func WithAddr(addr string) DialOption {
	return func(c *dialConfig) {
		c.addr = addr
	}
}

func WithGRPCOptions(opts ...grpc.DialOption) DialOption {
	return func(c *dialConfig) {
		c.opts = append(c.opts, opts...)
	}
}

type Dialer struct {
	target string
	opts   []grpc.DialOption
}

func NewDialer(opts ...DialOption) (*Dialer, error) {
	c := new(dialConfig)
	for _, opt := range opts {
		opt(c)
	}

	if c.addr == "" {
		var ok bool
		c.addr, ok = GetDefaultAddress()
		if !ok {
			return nil, errors.New("workload endpoint socket address is not configured")
		}
	}

	target, err := parseTargetFromAddr(c.addr)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		target: target,
		opts:   c.opts,
	}, nil
}

func (d *Dialer) Dial() (*grpc.ClientConn, error) {
	return d.DialContext(context.Background())
}

func (d *Dialer) DialContext(ctx context.Context) (*grpc.ClientConn, error) {
	// append the insecure option since the workload endpoint is by
	// definition insecure.
	dialOpts := append([]grpc.DialOption{}, d.opts...)
	dialOpts = append(dialOpts, grpc.WithInsecure())

	return grpc.DialContext(ctx, d.target, dialOpts...)
}

func Dial(opts ...DialOption) (*grpc.ClientConn, error) {
	dialer, err := NewDialer(opts...)
	if err != nil {
		return nil, err
	}
	return dialer.Dial()
}

func DialContext(ctx context.Context, opts ...DialOption) (*grpc.ClientConn, error) {
	dialer, err := NewDialer(opts...)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx)
}
