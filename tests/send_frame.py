#!/usr/bin/env python3
"""Send deterministic dtun UDP frames for privileged netns negative tests."""
import argparse
import hashlib
import hmac
import ipaddress
import socket
import struct


def inner_ipv4():
    # A syntactically valid minimal IPv4 packet is enough to exercise netif_rx.
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0, 0, 64, 1, 0,
                         b"\x0a\x14\x00\x02", b"\x0a\x14\x00\x01")
    words = struct.unpack("!10H", header)
    checksum = (~sum(words) & 0xffff)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-port", type=int, required=True)
    parser.add_argument("--tunnel-id", type=int, required=True)
    parser.add_argument("--remote-tunnel-id", type=int,
                        help="destination's receive ID; defaults to --tunnel-id")
    parser.add_argument("--src-node", type=int, required=True)
    parser.add_argument("--dst-node", type=int, required=True)
    parser.add_argument("--seq", type=int, default=1)
    parser.add_argument("--key", required=True)
    parser.add_argument("--bad-tag", action="store_true")
    parser.add_argument("--truncated", action="store_true")
    args = parser.parse_args()
    host, port = args.destination.rsplit(":", 1)
    if args.truncated:
        frame = b"\x01"
    else:
        payload = inner_ipv4()
        remote_tunnel_id = args.remote_tunnel_id or args.tunnel_id
        header = struct.pack("!BBHIIQQQ", 1, 1, 0, args.tunnel_id,
                             remote_tunnel_id, args.seq, args.src_node,
                             args.dst_node)
        tag = hmac.new(bytes.fromhex(args.key), header + payload, hashlib.sha256).digest()[:16]
        if args.bad_tag:
            tag = bytes([tag[0] ^ 1]) + tag[1:]
        frame = header + tag + payload
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((str(ipaddress.IPv4Address(args.source)), args.source_port))
    sock.sendto(frame, (host, int(port)))


if __name__ == "__main__":
    main()
