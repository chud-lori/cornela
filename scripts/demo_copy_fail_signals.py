#!/usr/bin/env python3
"""Harmless Copy Fail signal demo for Cornela.

This is not an exploit and it does not attempt container escape, privilege
escalation, page-cache writes, setuid binary patching, or host modification.

It only exercises the defensive signals Cornela correlates for Copy Fail-style
exposure:

  1. create an AF_ALG socket
  2. call splice()
  3. optionally call setuid(getuid()) as a benign UID syscall

Run Cornela in another terminal:

  sudo cornela monitor --events --duration 30

Then run this script as an unprivileged user, optionally from inside a test
container, to confirm Cornela reports the AF_ALG + splice sequence.
"""

import argparse
import os
import socket
import sys


def trigger_af_alg_hash() -> None:
    if not hasattr(socket, "AF_ALG"):
        raise RuntimeError("Python socket.AF_ALG is not available on this system")

    control = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        control.bind(("hash", "sha256"))
        op, _ = control.accept()
        try:
            op.sendall(b"cornela-copy-fail-signal-demo")
            digest = op.recv(32)
            if len(digest) != 32:
                raise RuntimeError("unexpected sha256 digest length")
        finally:
            op.close()
    finally:
        control.close()


def trigger_splice_to_dev_null() -> None:
    if not hasattr(os, "splice"):
        raise RuntimeError("Python os.splice is not available on this system")

    read_fd, write_fd = os.pipe()
    null_fd = os.open("/dev/null", os.O_WRONLY)
    try:
        payload = b"cornela-copy-fail-signal-demo"
        os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        moved = os.splice(read_fd, null_fd, len(payload))
        if moved <= 0:
            raise RuntimeError("splice moved no bytes")
    finally:
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)
        os.close(null_fd)


def trigger_benign_uid_syscall() -> None:
    current_uid = os.getuid()
    os.setuid(current_uid)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate harmless Copy Fail-style syscall signals for Cornela."
    )
    parser.add_argument(
        "--uid-self",
        action="store_true",
        help="also call setuid(getuid()) without changing privilege",
    )
    args = parser.parse_args()

    print("Cornela Copy Fail signal demo")
    print("mode: harmless syscall signal generation")
    print("escape attempted: no")
    print("privilege escalation attempted: no")
    print("host file modification attempted: no")

    trigger_af_alg_hash()
    print("signal: AF_ALG socket created")

    trigger_splice_to_dev_null()
    print("signal: splice called")

    if args.uid_self:
        trigger_benign_uid_syscall()
        print("signal: setuid(getuid()) called")

    print("done: Cornela should report AF_ALG + splice correlation")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"demo failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
