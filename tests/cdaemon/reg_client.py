#!/usr/bin/env python3
"""Self-contained DTRG client used only by negative control-plane tests."""
import argparse
import hashlib
import hmac
import ipaddress
import os
import socket
import struct

MAGIC = b"DTRG"
INIT, CHALLENGE, CONFIRM, ACK = range(1, 5)
TAG_LEN = 16


def tag(key, body):
    return hmac.new(key, body, hashlib.sha256).digest()[:TAG_LEN]


def authenticated(key, body):
    return body + tag(key, body)


def pack_init(key, node_id, address, prefix, nonce):
    body = struct.pack("!4sBQ4sB4s16s", MAGIC, INIT, node_id,
                       ipaddress.IPv4Address(address).packed, prefix,
                       b"\0" * 4, nonce)
    return authenticated(key, body)


def pack_confirm(key, challenge):
    body = struct.pack("!4sBQ4sB4s16s32s", MAGIC, CONFIRM,
                       challenge["node_id"], challenge["address"],
                       challenge["prefix"], challenge["raw"],
                       challenge["nonce"], challenge["cookie"])
    return authenticated(key, body)


def parse(key, packet):
    if len(packet) < TAG_LEN + 6:
        raise ValueError("short packet")
    body, actual = packet[:-TAG_LEN], packet[-TAG_LEN:]
    if not hmac.compare_digest(tag(key, body), actual):
        raise ValueError("bad HMAC")
    magic, kind = struct.unpack_from("!4sB", body)
    if magic != MAGIC:
        raise ValueError("unsupported protocol")
    if kind == CHALLENGE:
        values = struct.unpack("!4sBQ4sB4s16s32s", body)
        return {"kind": kind, "node_id": values[2], "address": values[3],
                "prefix": values[4], "raw": values[5], "nonce": values[6],
                "cookie": values[7]}
    if kind == ACK:
        values = struct.unpack("!4sBQII4sBH16s16sQ", body)
        return {"kind": kind, "node_id": values[2],
                "tunnel_id": values[3], "remote_tunnel_id": values[4],
                "address": values[5], "prefix": values[6],
                "data_port": values[7], "nonce": values[8]}
    return {"kind": kind}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hub", required=True)
    parser.add_argument("--port", type=int, default=49001)
    parser.add_argument("--node-id", type=int, required=True)
    parser.add_argument("--address", default="10.99.0.9/24")
    parser.add_argument("--key", required=True)
    parser.add_argument("--bad-init-key", action="store_true")
    parser.add_argument("--bad-cookie", action="store_true")
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()

    key = bytes.fromhex(args.key)
    bad_key = bytes([key[0] ^ 1]) + key[1:]
    nonce = os.urandom(16)
    address, prefix = args.address.split("/")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    destination = (args.hub, args.port)
    init_key = bad_key if args.bad_init_key else key
    sock.sendto(pack_init(init_key, args.node_id, address, int(prefix), nonce),
                destination)
    try:
        packet, _ = sock.recvfrom(512)
    except socket.timeout:
        print("NO_CHALLENGE")
        return
    try:
        challenge = parse(init_key, packet)
    except (ValueError, struct.error):
        print("BAD_CHALLENGE")
        return
    if challenge["kind"] != CHALLENGE:
        print("BAD_CHALLENGE")
        return
    if args.bad_cookie:
        challenge["cookie"] = bytes([challenge["cookie"][0] ^ 1]) + challenge["cookie"][1:]
    sock.sendto(pack_confirm(key, challenge), destination)
    try:
        packet, _ = sock.recvfrom(512)
    except socket.timeout:
        print("NO_ACK")
        return
    try:
        message = parse(key, packet)
        print("ACK" if message["kind"] == ACK else "NO_ACK")
    except (ValueError, struct.error):
        print("NO_ACK")


if __name__ == "__main__":
    main()
