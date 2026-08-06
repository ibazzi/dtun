#!/usr/bin/env python3
"""Wait for a dtun DATA frame on a UDP socket and print its destination node."""
import argparse
import socket
import struct


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--dst-node", type=int)
    args = parser.parse_args()
    address, port = args.bind.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, int(port)))
    sock.settimeout(args.timeout)
    while True:
        packet, _ = sock.recvfrom(65535)
        if len(packet) < 52 or packet[0] != 1 or packet[1] != 1:
            continue
        dst_node = struct.unpack_from("!Q", packet, 28)[0]
        if args.dst_node is None or dst_node == args.dst_node:
            print(dst_node, flush=True)
            return


if __name__ == "__main__":
    main()
