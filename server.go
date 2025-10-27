package main

import (
	"context"
	"log"

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
		err := s.peer.Start(ctx, s.host, s.handshaker, s.filePath, nil)
		if err != nil {
			return err
		}
	} else {
		rw, err := s.peer.Connect(s.host, s.destination, s.handshaker)
		if err != nil {
			return err
		}

		if err := receiveFile(rw); err != nil {
			return err
		}

		log.Println("File transfer completed, closing connection...")
		s.host.Close()
		return nil
	}

	select {}
}
