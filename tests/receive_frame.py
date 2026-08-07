#!/usr/bin/env python3
"""Wait for a dtun DATA frame on a UDP socket and print its destination node."""
import argparse
import hashlib
import hmac
import socket
import struct


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--dst-node", type=int)
    parser.add_argument("--key",
                        help="reply to an authenticated PROBE before waiting for DATA")
    args = parser.parse_args()
    address, port = args.bind.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, int(port)))
    sock.settimeout(args.timeout)
    while True:
        packet, source = sock.recvfrom(65535)
        if len(packet) < 52 or packet[0] != 1:
            continue
        if packet[1] == 2 and args.key:
            _, _, _, src_tunnel, dst_tunnel, seq, src_node, dst_node = \
                struct.unpack_from("!BBHIIQQQ", packet)
            reply_header = struct.pack("!BBHIIQQQ", 1, 3, 0,
                                       dst_tunnel, src_tunnel, seq + 1,
                                       dst_node, src_node)
            tag = hmac.new(bytes.fromhex(args.key), reply_header,
                           hashlib.sha256).digest()[:16]
            sock.sendto(reply_header + tag, source)
            continue
        if packet[1] != 1:
            continue
        dst_node = struct.unpack_from("!Q", packet, 28)[0]
        if args.dst_node is None or dst_node == args.dst_node:
            print(dst_node, flush=True)
            return


if __name__ == "__main__":
    main()
