# SSH Honeypot

A lightweight SSH honeypot server built with [Paramiko](https://www.paramiko.org/).

Emulates a real SSH server to attract brute-force bots and manual attackers. After several failed login attempts the honeypot deliberately grants access, presenting the attacker with a simulated Linux shell. All commands executed are logged to stdout.

---

## Features

- Presents as a standard OpenSSH server banner
- Grants shell access after 5 failed login attempts per IP/username pair (mimics a "weak" server)
- Simulated shell environment with basic commands:
  - `ls`, `cat`, `echo`, `cp`, `exit`
  - Supports shell redirection: `echo "data" > file.txt` and `>>`
- In-memory virtual filesystem per session
- Multi-threaded — handles simultaneous connections
- Auto-generates an RSA host key on first run
- No root required (binds to user-space ports > 1024)

---

## Requirements

```bash
pip install -r requirements.txt
```

Python 3.8+

---

## Usage

```bash
python honeypot.py -p 2222
```

Then attempt to connect:

```bash
ssh user@localhost -p 2222
```

The first 4 login attempts will be rejected. On the 5th attempt with any password, the session is granted.

### Options

| Flag | Description |
|------|-------------|
| `-p <port>` | Port to listen on (must be > 1024) |

---

## Sample output

```
[*] Loaded existing host_key.
[*] Listening on 0.0.0.0:2222
[+] Connection from 192.168.1.42:51234
[>] 192.168.1.42 ran: ls
[>] 192.168.1.42 ran: cat passwd.txt
[>] 192.168.1.42 ran: echo "exfil" > out.txt
```

---

## Host key

On first run, a 2048-bit RSA key is generated and saved to `./host_key`. On subsequent runs the same key is reused, keeping the server fingerprint stable.

Add `host_key` to `.gitignore` before pushing to avoid committing your private key.

---

## Notes

- This is an **intentionally weak** server for research and education purposes.
- Deploy in an isolated environment (VM, container, cloud instance) — not on a production machine.
- Consider redirecting port 22 to the honeypot using `iptables` or cloud firewall rules for realistic exposure.
- Use only on infrastructure you own or have permission to monitor.

## License

MIT
