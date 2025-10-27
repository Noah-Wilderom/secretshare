package main

import (
	"context"
	"github.com/Noah-Wilderom/secretshare/auth"

	"github.com/libp2p/go-libp2p/core/host"
)

type Server struct {
	peer        *Peer
	host        host.Host
	destination string
	filePath    string
	handshaker  *auth.GPGHandshake
}

func NewServer(peer *Peer, destination string, filePath string, handshaker *auth.GPGHandshake) *Server {
	peerHost, err := peer.NewHost()
	if err != nil {
		panic(err)
	}

	return &Server{
		peer:        peer,
		host:        peerHost,
		destination: destination,
		filePath:    filePath,
		handshaker:  handshaker,
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s.destination == "" {
		// Host mode - start listening for incoming connections
		err := s.peer.Start(ctx, s.host, s.handshaker, s.filePath, nil)
		if err != nil {
			return err
		}
	} else {
		// Client mode - connect to destination and perform handshake
		rw, err := s.peer.Connect(s.host, s.destination, s.handshaker)
		if err != nil {
			return err
		}

		// Receive the file from host
		if err := receiveFile(rw); err != nil {
			return err
		}
	}

	// Wait forever
	select {}
}
