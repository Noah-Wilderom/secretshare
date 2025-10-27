package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"

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

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", errors.New("no network interface found")
}

func copyToClipboard(text string) error {
	cmd := exec.Command("pbcopy")
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if _, err := in.Write([]byte(text)); err != nil {
		return err
	}

	if err := in.Close(); err != nil {
		return err
	}

	return cmd.Wait()
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
	// Enables NAT traversal for seamless connectivity on local networks
	return libp2p.New(
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
		libp2p.EnableNATService(),   // Enable NAT traversal
		libp2p.EnableHolePunching(), // Enable hole punching for NAT traversal
	)
}

func (p *Peer) getPID() protocol.ID {
	return protocol.ID(
		fmt.Sprintf("/%s/%s", AppName, AppVersion),
	)
}

func (p *Peer) Start(_ context.Context, h host.Host, handshaker *auth.GPGHandshake, filePath string, handler network.StreamHandler) error {
	h.SetStreamHandler(p.getPID(), makeStreamHandler(handshaker, filePath))

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

	localIP, err := getLocalIP()
	if err != nil {
		log.Printf("Warning: Could not get local IP: %v, using 127.0.0.1\n", err)
		localIP = "127.0.0.1"
	}

	addr := fmt.Sprintf("/ip4/%s/tcp/%s/p2p/%s", localIP, port, h.ID())

	if err := copyToClipboard(addr); err != nil {
		log.Printf("Warning: Could not copy to clipboard: %v\n", err)
	} else {
		log.Println("Connection address copied to clipboard!")
	}

	log.Printf("Share this address: %s\n", addr)
	log.Println("Waiting for incoming connection...")

	return nil
}

func (p *Peer) Connect(h host.Host, destination string, handshaker *auth.GPGHandshake) (*bufio.ReadWriter, error) {
	log.Println("This node's multiaddresses:")
	for _, la := range h.Addrs() {
		log.Printf(" - %v\n", la)
	}
	log.Println()

	maddr, err := multiaddr.NewMultiaddr(destination)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	s, err := h.NewStream(context.Background(), info.ID, p.getPID())
	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Println("Established connection to destination")

	if !handshaker.Handshake(s) {
		log.Println("Handshake failed, closing connection")
		s.Reset()
		return nil, fmt.Errorf("handshake failed")
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	return rw, nil
}

func (p *Peer) Disconnect() {
	//
}
