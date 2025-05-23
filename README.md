# 🚀 SHitSHAT - Secure SSH-Agent Based Encrypted Chat

**SHitSHAT** is a simple, secure chat application written in Go. It uses SSH keys loaded in your SSH agent to identify users and sign messages, providing cryptographic authentication and message integrity. Communication happens over WebSockets.

---

## ✨ Features

- 🔑 **User identity** derived from SSH public keys (no usernames or passwords needed)
- 🛡️ **End-to-end message signing & verification** using your SSH agent's private keys
- 📢 **Server broadcasts** messages to multiple connected clients
- 🎨 **Color-coded usernames** _(coming soon)_
- 🔒 **Passphrase protection** for additional handshake security
- 🔁 **Easy to run** as either server or client

---

## ⚙️ Requirements

- Go **1.18+**
- SSH agent running with at least one key loaded (`ssh-add` to add your private key)
- Network connectivity between client and server

---

## 🚦 Usage

### 🛠️ Build or Run

```sh
go run main.go [options]
# or build a binary:
go build -o shitshat main.go
./shitshat [options]
```

---

### 🖥️ Server

Start the server (default: `0.0.0.0:1337`):

```sh
go run main.go --listen 0.0.0.0 --port 1337
# or simply:
go run main.go
```

The server will prompt you to enter a passphrase for handshake verification (can be empty).

---

### 💻 Client

Connect to the server as a client:

```sh
go run main.go --client --serveraddr 127.0.0.1:1337
```

The client will prompt for the passphrase that matches the server's (or leave empty if none).

Once connected, you can start typing messages. Use `/quit` to exit.

---

## 📝 Notes

- **Chat identity** is the SHA256 fingerprint (shortened) of your SSH public key.
- **Messages** are signed with your SSH agent’s private key.
- The server does **not send your own messages back** to you; run multiple clients to test messaging.
- The **passphrase** is used as a simple challenge to verify peers during connection.
- SSH agent must be running and accessible via `SSH_AUTH_SOCK`.

---

## 🛠️ Troubleshooting

- **No keys loaded in SSH agent:**  
  Run `ssh-add` to add your private key.
- **Connection refused:**  
  Check server IP/port and firewall settings.
- **Passphrase mismatch:**  
  Ensure client and server use the same passphrase (or none).
- **Messages not received:**  
  Connect multiple clients to see broadcasts.

---

## 📄 License

MIT License

---

## 👤 Author

Pefman