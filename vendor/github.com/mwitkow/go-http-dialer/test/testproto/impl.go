// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package mwitkow_testproto

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	PingDefaultValue   = "I like kittens."
	CountListResponses = 20
)

type TestService struct {
}

func (s *TestService) PingEmpty(ctx context.Context, _ *Empty) (*PingResponse, error) {
	return &PingResponse{Value: PingDefaultValue, Counter: 42}, nil
}

func (s *TestService) Ping(ctx context.Context, ping *PingRequest) (*PingResponse, error) {
	// Send user trailers and headers.
	return &PingResponse{Value: ping.Value, Counter: 42}, nil
}

func (s *TestService) PingError(ctx context.Context, ping *PingRequest) (*Empty, error) {
	code := codes.Code(ping.ErrorCodeReturned)
	return nil, grpc.Errorf(code, "Userspace error.")
}

func (s *TestService) PingList(ping *PingRequest, stream TestService_PingListServer) error {
	if ping.ErrorCodeReturned != 0 {
		return grpc.Errorf(codes.Code(ping.ErrorCodeReturned), "foobar")
	}
	// Send user trailers and headers.
	for i := 0; i < CountListResponses; i++ {
		stream.Send(&PingResponse{Value: ping.Value, Counter: int32(i)})
	}
	return nil
}
