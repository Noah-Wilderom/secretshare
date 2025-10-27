package auth

import "github.com/libp2p/go-libp2p/core/network"

type Handshaker interface {
	Handshake(network.Stream) bool
}

type NOOPHandshake struct{}

func (h *NOOPHandshake) Handshake(_ network.Stream) bool {
	return true
}
