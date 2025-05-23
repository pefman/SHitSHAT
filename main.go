package main

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	listenAddr = flag.String("listen", "0.0.0.0", "Address to listen on (default 0.0.0.0)")
	port       = flag.Int("port", 1337, "Port to listen on or connect to (default 1337)")
	clientMode = flag.Bool("client", false, "Run as client")
	serverAddr = flag.String("serveraddr", "", "Server address to connect to as client")
	passphrase = flag.String("passphrase", "", "Passphrase for initialization (optional, will prompt if empty)")
	verbose    = flag.Bool("verbose", false, "Enable verbose logging")
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type SSHAgentSigner struct {
	conn   net.Conn
	signer ssh.Signer
}

func NewSSHAgentSigner() (*SSHAgentSigner, error) {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set, ssh-agent not available")
	}

	conn, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH_AUTH_SOCK: %w", err)
	}

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to get signers from ssh-agent: %w", err)
	}
	if len(signers) == 0 {
		conn.Close()
		return nil, fmt.Errorf("no keys loaded in ssh-agent")
	}

	return &SSHAgentSigner{conn: conn, signer: signers[0]}, nil
}

func (s *SSHAgentSigner) Close() error {
	return s.conn.Close()
}

func (s *SSHAgentSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func (s *SSHAgentSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.Sign(rand, data)
}

func publicKeyFingerprint(pub ssh.PublicKey) string {
	hash := sha256.Sum256(pub.Marshal())
	return fmt.Sprintf("%x", hash[:6])
}

func handshake(conn *websocket.Conn, signer ssh.Signer, passphrase string) (ssh.PublicKey, string, error) {
	pubKey := signer.PublicKey()
	pubKeyStr := string(ssh.MarshalAuthorizedKey(pubKey))

	if *verbose {
		log.Printf("Sending public key: %s", publicKeyFingerprint(pubKey))
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("PUBKEY:"+pubKeyStr)); err != nil {
		return nil, "", fmt.Errorf("failed to send public key: %w", err)
	}

	_, msg, err := conn.ReadMessage()
	if err != nil {
		return nil, "", fmt.Errorf("failed to read peer pub key: %w", err)
	}
	if *verbose {
		log.Printf("Received peer pub key message")
	}

	peerMsg := string(msg)
	if !strings.HasPrefix(peerMsg, "PUBKEY:") {
		return nil, "", fmt.Errorf("expected PUBKEY message, got: %s", peerMsg)
	}
	peerPubKeyStr := peerMsg[len("PUBKEY:"):]
	peerPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(peerPubKeyStr))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse peer public key: %w", err)
	}
	if *verbose {
		log.Printf("Parsed peer public key: %s", publicKeyFingerprint(peerPubKey))
	}

	if passphrase != "" {
		challenge := passphrase + publicKeyFingerprint(pubKey)
		sig, err := signer.Sign(nil, []byte(challenge))
		if err != nil {
			return nil, "", fmt.Errorf("failed to sign challenge: %w", err)
		}

		if *verbose {
			log.Printf("Sending signature challenge")
		}
		sigMsg := "SIG:" + string(sig.Blob)
		if err := conn.WriteMessage(websocket.TextMessage, []byte(sigMsg)); err != nil {
			return nil, "", fmt.Errorf("failed to send signature: %w", err)
		}

		_, peerSigMsgRaw, err := conn.ReadMessage()
		if err != nil {
			return nil, "", fmt.Errorf("failed to read peer signature: %w", err)
		}
		peerSigMsg := string(peerSigMsgRaw)
		if !strings.HasPrefix(peerSigMsg, "SIG:") {
			return nil, "", fmt.Errorf("expected SIG message, got: %s", peerSigMsg)
		}
		peerSigBlob := []byte(peerSigMsg[len("SIG:"):])
		peerSig := &ssh.Signature{Format: peerPubKey.Type(), Blob: peerSigBlob}

		peerChallenge := passphrase + publicKeyFingerprint(peerPubKey)
		if err := peerPubKey.Verify([]byte(peerChallenge), peerSig); err != nil {
			return nil, "", fmt.Errorf("peer signature verification failed: %w", err)
		}
		if *verbose {
			log.Printf("Peer signature verified successfully")
		}
	}
	return peerPubKey, peerPubKeyStr, nil
}

func runServerAsClient(listen string, port int, signer *SSHAgentSigner, passphrase string) error {
	clients := make(map[string]*websocket.Conn)
	var mu sync.Mutex

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Upgrade error: %v", err)
			return
		}

		peerKey, _, err := handshake(conn, signer.signer, passphrase)
		if err != nil {
			log.Printf("Handshake failed: %v", err)
			conn.Close()
			return
		}

		username := publicKeyFingerprint(peerKey)
		if *verbose {
			log.Printf("Client connected: %s", username)
		}

		mu.Lock()
		clients[username] = conn
		mu.Unlock()

		defer func() {
			mu.Lock()
			delete(clients, username)
			mu.Unlock()
			conn.Close()
			if *verbose {
				log.Printf("Client disconnected: %s", username)
			}
		}()

		// Notify all clients of the new join (including server console)
		msg := fmt.Sprintf("** %s joined **", username)
		if *verbose {
			log.Printf(msg)
		}
		broadcast(msg, username, clients, &mu)

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				if *verbose {
					log.Printf("Read error from %s: %v", username, err)
				}
				break
			}
			text := string(message)
			if *verbose {
				log.Printf("Received from %s: %s", username, text)
			}
			broadcast(fmt.Sprintf("[%s] %s", username, text), username, clients, &mu)
		}
	})

	addr := fmt.Sprintf("%s:%d", listen, port)
	if *verbose {
		log.Printf("ShitShat server listening on %s", addr)
	}
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Server acts also as client connecting to itself
	return runClient(fmt.Sprintf("localhost:%d", port), signer, passphrase)
}

func broadcast(message string, sender string, clients map[string]*websocket.Conn, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	for username, conn := range clients {
		if username == sender {
			continue // Don't send to sender
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			if *verbose {
				log.Printf("Broadcast error to %s: %v", username, err)
			}
		}
	}
}

func runSingleClient(conn *websocket.Conn, signer *SSHAgentSigner, passphrase string) {
	defer conn.Close()

	peerKey, _, err := handshake(conn, signer.signer, passphrase)
	if err != nil {
		log.Printf("Handshake failed: %v", err)
		return
	}
	if *verbose {
		log.Printf("Client connected from %s", publicKeyFingerprint(peerKey))
	}

	myUsername := publicKeyFingerprint(signer.PublicKey())

	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				if *verbose {
					log.Printf("Client read error: %v", err)
				}
				return
			}
			fmt.Println(string(message))
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Connected as %s. Type messages:\n", myUsername)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "/quit" {
			break
		}
		if *verbose {
			log.Printf("Sending message: %s", text)
		}
		err := conn.WriteMessage(websocket.TextMessage, []byte(text))
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}
	}
}

func runClient(serverAddr string, signer *SSHAgentSigner, passphrase string) error {
	url := fmt.Sprintf("ws://%s/ws", serverAddr)
	if *verbose {
		log.Printf("Connecting to %s", url)
	}

	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	_, _, err = handshake(conn, signer.signer, passphrase)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	myUsername := publicKeyFingerprint(signer.PublicKey())

	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				if *verbose {
					log.Printf("Read error: %v", err)
				}
				os.Exit(1)
			}
			fmt.Println(string(message))
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Connected as %s. Type messages:\n", myUsername)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "/quit" {
			break
		}
		if *verbose {
			log.Printf("Sending message: %s", text)
		}
		err := conn.WriteMessage(websocket.TextMessage, []byte(text))
		if err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}

	return nil
}

func promptPassphrase() string {
	fmt.Print("Enter passphrase (leave empty if none): ")
	reader := bufio.NewReader(os.Stdin)
	pass, _ := reader.ReadString('\n')
	return strings.TrimSpace(pass)
}

func main() {
	flag.Parse()

	signer, err := NewSSHAgentSigner()
	if err != nil {
		log.Fatalf("Failed to initialize SSH signer: %v", err)
	}
	defer signer.Close()

	var pass string
	if *passphrase == "" {
		pass = promptPassphrase()
	} else {
		pass = *passphrase
	}

	if *clientMode {
		if *serverAddr == "" {
			log.Fatal("Please specify --serveraddr to connect to")
		}
		if err := runClient(*serverAddr, signer, pass); err != nil {
			log.Fatalf("Client error: %v", err)
		}
	} else {
		if err := runServerAsClient(*listenAddr, *port, signer, pass); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}
