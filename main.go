package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/Noah-Wilderom/secretshare/auth"
	"io"
	"log"
	mrand "math/rand"
	"os"
)

const (
	AppName    = "secretshare"
	AppVersion = "1.0.0"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sourcePort := flag.Int("sp", 0, "Source port number")
	dest := flag.String("d", "", "Destination multiaddr string")
	filePath := flag.String("file", "", "Path to file to share (host only)")
	help := flag.Bool("help", false, "Display help")
	debug := flag.Bool("debug", false, "Debug generates the same node ID on every execution")

	flag.Parse()

	if *help {
		fmt.Printf("Share secrets through P2P connection\n\n")
		fmt.Printf("Host Usage: Run '%s -sp <SOURCE_PORT> -file <FILE_PATH>' to share a file.\n", AppName)
		fmt.Printf("Client Usage: Run '%s -d <MULTIADDR>' to connect and receive the file.\n", AppName)
		fmt.Printf("\nExample:\n")
		fmt.Printf("  Host:   %s -sp 8080 -file /path/to/secret.txt\n", AppName)
		fmt.Printf("  Client: %s -d /ip4/127.0.0.1/tcp/8080/p2p/<PEER_ID>\n", AppName)

		os.Exit(0)
	}

	// Validate host requirements
	isHost := *dest == ""
	if isHost && *filePath == "" {
		fmt.Printf("Error: Host mode requires a file to share. Use -file flag.\n")
		fmt.Printf("Run '%s -help' for usage information.\n", AppName)
		os.Exit(1)
	}

	// If debug is enabled, use a constant random source to generate the peer ID. Only useful for debugging,
	// off by default. Otherwise, it uses rand.Reader.
	var r io.Reader
	if *debug {
		// Use the port number as the randomness source.
		// This will always generate the same host ID on multiple executions, if the same port number is used.
		// Never do this in production code.
		r = mrand.New(mrand.NewSource(int64(*sourcePort)))
	} else {
		r = rand.Reader
	}

	p := NewPeer(*sourcePort, r)

	// Determine if we're the host (listener) or client (connector)
	handshaker := auth.NewGPGHandshake(isHost)

	s := NewServer(p, *dest, *filePath, handshaker)

	if err := s.Start(ctx); err != nil {
		log.Println(err)
		return
	}
}
