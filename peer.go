package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/Noah-Wilderom/secretshare/auth"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

type Peer struct {
	port       int
	randomness io.Reader
}

func NewPeer(port int, r io.Reader) *Peer {
	return &Peer{
		port:       port,
		randomness: r,
	}
}

func (p *Peer) NewHost() (host.Host, error) {
	// Creates a new RSA key pair for this host.
	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, p.randomness)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// 0.0.0.0 will listen on any interface device.
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", p.port))

	// libp2p.New constructs a new libp2p Host.
	// Other options can be added here.
	return libp2p.New(
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
	)
}

func (p *Peer) getPID() protocol.ID {
	return protocol.ID(
		fmt.Sprintf("/%s/%s", AppName, AppVersion),
	)
}

func (p *Peer) Start(_ context.Context, h host.Host, handshaker *auth.GPGHandshake, filePath string, handler network.StreamHandler) error {
	// Set a function as stream handler.
	// This function is called when a peer connects, and starts a stream with this protocol.
	// Only applies on the receiving side.
	// Use makeStreamHandler to create a handler that performs handshake and file transfer
	h.SetStreamHandler(p.getPID(), makeStreamHandler(handshaker, filePath))

	// Let's get the actual TCP port from our listen multiaddr, in case we're using 0 (default; random available port).
	var port string
	for _, la := range h.Network().ListenAddresses() {
		if p, err := la.ValueForProtocol(multiaddr.P_TCP); err == nil {
			port = p
			break
		}
	}

	if port == "" {
		return errors.New("was not able to find actual local port")
	}

	log.Printf("Run '%s -d /ip4/127.0.0.1/tcp/%v/p2p/%s' on another console.\n", AppName, port, h.ID())
	log.Println("You can replace 127.0.0.1 with public IP as well.")
	log.Println("Waiting for incoming connection")
	log.Println()

	return nil
}

func (p *Peer) Connect(h host.Host, destination string, handshaker *auth.GPGHandshake) (*bufio.ReadWriter, error) {
	log.Println("This node's multiaddresses:")
	for _, la := range h.Addrs() {
		log.Printf(" - %v\n", la)
	}
	log.Println()

	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(destination)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Add the destination's peer multiaddress in the peerstore.
	// This will be used during connection and stream creation by libp2p.
	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	// Start a stream with the destination.
	// Multiaddress of the destination peer is fetched from the peerstore using 'peerId'.
	s, err := h.NewStream(context.Background(), info.ID, p.getPID())
	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Println("Established connection to destination")

	// Perform handshake before proceeding
	if !handshaker.Handshake(s) {
		log.Println("Handshake failed, closing connection")
		s.Reset()
		return nil, fmt.Errorf("handshake failed")
	}

	// Create a buffered stream so that read and writes are non-blocking.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	return rw, nil
}

func (p *Peer) Disconnect() {
	//
}
