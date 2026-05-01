#!/usr/bin/env python3
"""Generate benign AF_ALG and splice events for Cornela monitor testing.

This script does not exploit anything. It creates an AF_ALG hash socket and
uses splice on a pipe so the eBPF monitor can observe the syscall sequence.
Run it as an unprivileged user while Cornela monitor runs in another terminal.
"""

import argparse
import os
import socket
import sys


def trigger_afalg() -> None:
    if not hasattr(socket, "AF_ALG"):
        raise RuntimeError("Python socket.AF_ALG is not available on this system")

    sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        sock.bind(("hash", "sha256"))
        op, _ = sock.accept()
        try:
            op.sendall(b"cornela-safe-test")
            op.recv(32)
        finally:
            op.close()
    finally:
        sock.close()


def trigger_splice() -> None:
    if not hasattr(os, "splice"):
        raise RuntimeError("Python os.splice is not available on this system")

    read_fd, write_fd = os.pipe()
    null_fd = os.open("/dev/null", os.O_WRONLY)
    try:
        os.write(write_fd, b"cornela-safe-test")
        os.close(write_fd)
        write_fd = -1
        os.splice(read_fd, null_fd, 17)
    finally:
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)
        os.close(null_fd)


def trigger_setuid_self() -> None:
    os.setuid(os.getuid())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--setuid-self",
        action="store_true",
        help="also call setuid(getuid()) to generate a benign UID transition event",
    )
    args = parser.parse_args()

    trigger_afalg()
    trigger_splice()
    if args.setuid_self:
        trigger_setuid_self()

    print("generated benign AF_ALG and splice events")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"safe trigger failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
