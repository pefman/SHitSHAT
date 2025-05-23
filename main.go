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

type Client struct {
	conn      *websocket.Conn
	username  string
	pubKey    ssh.PublicKey
	pubKeyStr string
	mu        sync.Mutex
}

func (c *Client) sendMessage(msg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, []byte(msg))
}

type Server struct {
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	mu         sync.Mutex
}

func NewServer() *Server {
	return &Server{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (s *Server) run() {
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client] = true
			s.mu.Unlock()
			log.Printf("Client connected: %s", client.username)
			s.broadcast(fmt.Sprintf("*** %s joined the chat ***", client.username), client)
		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				client.conn.Close()
				s.broadcast(fmt.Sprintf("*** %s left the chat ***", client.username), client)
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) broadcast(message string, ignore *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for client := range s.clients {
		if client != ignore {
			err := client.sendMessage(message)
			if err != nil {
				log.Printf("Error sending to %s: %v", client.username, err)
			}
		}
	}
}

func handshake(conn *websocket.Conn, signer ssh.Signer, passphrase string) (ssh.PublicKey, string, error) {
	pubKey := signer.PublicKey()
	pubKeyStr := string(ssh.MarshalAuthorizedKey(pubKey))

	if err := conn.WriteMessage(websocket.TextMessage, []byte("PUBKEY:"+pubKeyStr)); err != nil {
		return nil, "", fmt.Errorf("failed to send public key: %w", err)
	}

	_, msg, err := conn.ReadMessage()
	if err != nil {
		return nil, "", fmt.Errorf("failed to read peer pub key: %w", err)
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

	if passphrase != "" {
		challenge := passphrase + publicKeyFingerprint(pubKey)
		sig, err := signer.Sign(nil, []byte(challenge))
		if err != nil {
			return nil, "", fmt.Errorf("failed to sign challenge: %w", err)
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
	}

	return peerPubKey, peerPubKeyStr, nil
}

func handleClientConnection(s *Server, conn *websocket.Conn, signer *SSHAgentSigner, passphrase string) {
	defer conn.Close()

	peerPubKey, peerPubKeyStr, err := handshake(conn, signer.signer, passphrase)
	if err != nil {
		log.Printf("Handshake failed: %v", err)
		return
	}

	username := publicKeyFingerprint(peerPubKey)

	client := &Client{
		conn:      conn,
		username:  username,
		pubKey:    peerPubKey,
		pubKeyStr: peerPubKeyStr,
	}

	s.register <- client

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Read error from %s: %v", client.username, err)
			break
		}

		s.broadcast(fmt.Sprintf("[%s] %s", client.username, string(message)), client)
	}

	s.unregister <- client
}

func runServer(listen string, port int, signer *SSHAgentSigner, passphrase string) error {
	s := NewServer()
	go s.run()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Upgrade error: %v", err)
			return
		}
		go handleClientConnection(s, conn, signer, passphrase)
	})

	addr := fmt.Sprintf("%s:%d", listen, port)
	log.Printf("ShitShat server listening on %s", addr)
	return http.ListenAndServe(addr, nil)
}

func runClient(serverAddr string, signer *SSHAgentSigner, passphrase string) error {
	url := fmt.Sprintf("ws://%s/ws", serverAddr)
	log.Printf("Connecting to %s", url)

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
				log.Printf("Read error: %v", err)
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
		if err := runServer(*listenAddr, *port, signer, pass); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}
