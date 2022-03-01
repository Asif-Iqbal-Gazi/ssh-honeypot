"""
honeypot.py - Lightweight SSH honeypot server.

Emulates an SSH server to attract and log brute-force login attempts.
After 5 failed login attempts from a given IP/username pair the honeypot
grants access, presenting the attacker with a simulated shell environment.

Supported shell commands:
    ls, cat, echo (with > and >> redirection), cp, exit

Usage:
    python honeypot.py -p <port>

    Port must be > 1024 (no root required).

Requirements:
    pip install paramiko
"""

import os
import sys
import shlex
import socket
import argparse
import paramiko
import threading


# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

listen_ip = "0.0.0.0"
listen_port = 0
host_key = None
SSH_BANNER = "SSH-2.0-OpenSSH_8.4"

login_attempts: dict = {}   # {client_ip: {username: attempt_count}}
exit_signal = threading.Event()

# Terminal escape sequences
UP_KEY    = b"\x1b[A"
DOWN_KEY  = b"\x1b[B"
RIGHT_KEY = b"\x1b[C"
LEFT_KEY  = b"\x1b[D"
BACK_KEY  = b"\x7f"


# ---------------------------------------------------------------------------
# Virtual filesystem
# ---------------------------------------------------------------------------

class FileSystem:
    """In-memory filesystem supporting basic shell operations."""

    def __init__(self):
        self._files: dict = {}

    def ls(self):
        return list(self._files.keys())

    def cat(self, name: str):
        return self._files.get(name)

    def cp(self, src: str, dst: str):
        if src in self._files:
            self._files[dst] = self._files[src]

    def create(self, name: str, content: str):
        self._files[name] = content

    def append(self, name: str, content: str):
        if name in self._files:
            self._files[name] += "\n" + content
        else:
            self.create(name, content)

    def exists(self, name: str) -> bool:
        return name in self._files


# ---------------------------------------------------------------------------
# SSH server interface
# ---------------------------------------------------------------------------

class HoneypotServer(paramiko.ServerInterface):
    """Paramiko server interface with delayed-grant authentication."""

    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        self.username = ""
        self.shell_ready = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_none(self, username: str) -> int:
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Deny the first 4 attempts (as a real server would), grant on the 5th.
        This lures attackers into staying long enough to log their behaviour.
        """
        ip_entry = login_attempts.setdefault(self.client_ip, {})
        count = ip_entry.get(username, 0)

        if count >= 5:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL

        ip_entry[username] = count + 1
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel) -> bool:
        self.shell_ready.set()
        return True


# ---------------------------------------------------------------------------
# Client session handler
# ---------------------------------------------------------------------------

class ClientSession:
    """Manages a single authenticated SSH session."""

    def __init__(self, sock: socket.socket, addr: tuple):
        self._handle(sock, addr)

    def _handle(self, sock: socket.socket, addr: tuple):
        client_ip = addr[0]
        login_attempts.setdefault(client_ip, {})

        try:
            transport = paramiko.Transport(sock)
            transport.add_server_key(host_key)
            transport.local_version = SSH_BANNER

            server = HoneypotServer(client_ip)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                print("[!] SSH negotiation failed.")
                sock.close()
                return

            channel = transport.accept(20)
            if channel is None:
                print("[!] Client disconnected before channel was established.")
                transport.close()
                sock.close()
                return

            server.shell_ready.wait(60)
            if not server.shell_ready.is_set():
                print("[!] Client never requested a shell.")
                return

            username = server.username
            fs = FileSystem()

            channel.send(f"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0 x86_64)\r\n\r\n")

            running = True
            while running and not exit_signal.is_set():
                channel.send(f"{username}@server:~$ ")
                f = channel.makefile("rU")
                cmd = f.readline().strip("\r\n")

                if cmd == "exit":
                    running = False
                elif cmd:
                    print(f"[>] {client_ip} ran: {cmd}")
                    self._run_command(cmd, channel, fs)

            channel.close()

        except Exception as exc:
            print(f"[!] Session error ({exc.__class__.__name__}): {exc}")
            try:
                transport.close()
            except Exception:
                pass

    def _run_command(self, command: str, channel, fs: FileSystem):
        try:
            parts = shlex.split(command)
        except Exception:
            return
        if not parts:
            return

        cmd = parts[0]

        if cmd == "ls":
            files = fs.ls()
            if files:
                channel.send("  ".join(files) + "\r\n")

        elif cmd == "cat" and len(parts) >= 2:
            for name in parts[1:]:
                if not name.endswith(".txt"):
                    channel.send("Unknown file type\r\n")
                    continue
                content = fs.cat(name)
                if content is None:
                    channel.send(f"cat: {name}: No such file or directory\r\n")
                else:
                    channel.send(content + "\r\n")

        elif cmd == "cp" and len(parts) == 3:
            src, dst = parts[1], parts[2]
            if not dst.endswith(".txt"):
                channel.send("Unknown file type\r\n")
            elif not fs.exists(src):
                channel.send(f"cp: {src}: No such file or directory\r\n")
            else:
                fs.cp(src, dst)

        elif cmd == "echo":
            if len(parts) == 4 and parts[2] in (">", ">>"):
                content, op, filename = parts[1], parts[2], parts[3]
                if not filename.endswith(".txt"):
                    channel.send("Unknown file type\r\n")
                elif op == ">":
                    fs.create(filename, content)
                else:
                    fs.append(filename, content)
            elif len(parts) >= 2:
                channel.send(command[5:] + "\r\n")

        else:
            channel.send(f"{cmd}: command not found\r\n")


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------

def run_server():
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("", listen_port))
        print(f"[*] SSH honeypot listening on 0.0.0.0:{listen_port}")
    except Exception as exc:
        print(f"[!] Failed to bind socket: {exc}")
        sys.exit(1)

    threads = []
    while True:
        try:
            server_sock.listen(10)
            client_sock, client_addr = server_sock.accept()
            print(f"[+] Connection from {client_addr[0]}:{client_addr[1]}")
            t = threading.Thread(target=ClientSession, args=(client_sock, client_addr), daemon=True)
            threads.append(t)
            t.start()
        except socket.error as exc:
            print(f"[!] Accept error: {exc}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            exit_signal.set()
            for t in threads:
                t.join()
            server_sock.close()
            sys.exit(0)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global listen_port, host_key

    parser = argparse.ArgumentParser(description="Lightweight SSH honeypot server.")
    parser.add_argument("-p", dest="port", type=int, required=True,
                        help="Port to listen on (must be > 1024)")
    args = parser.parse_args()

    if not (1025 <= args.port <= 65535):
        print("[!] Port must be in range 1025–65535 (no root required).")
        sys.exit(1)

    listen_port = args.port

    if not os.path.isfile("host_key"):
        print("[*] Generating RSA host key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file("host_key")
        print("[*] host_key saved.")
    else:
        print("[*] Loaded existing host_key.")

    host_key = paramiko.RSAKey(filename="host_key")

    print(f"[*] Listening on 0.0.0.0:{listen_port}")
    print("[*] Press Ctrl+C to stop.\n")
    run_server()


if __name__ == "__main__":
    main()
