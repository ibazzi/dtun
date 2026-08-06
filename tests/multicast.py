#!/usr/bin/env python3
"""Small IPv4 multicast sender/receiver used by namespace regressions."""

import argparse
import socket


def receive(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", args.port))
    membership = socket.inet_aton(args.group) + socket.inet_aton(args.interface)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    sock.settimeout(args.timeout)
    payload, _ = sock.recvfrom(65535)
    message = payload.decode("utf-8")
    if message != args.message:
        raise SystemExit(f"unexpected multicast payload: {message!r}")
    print(message, flush=True)


def send(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(args.interface))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.sendto(args.message.encode("utf-8"), (args.group, args.port))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)

    receiver = subparsers.add_parser("receive")
    receiver.add_argument("--group", required=True)
    receiver.add_argument("--interface", required=True)
    receiver.add_argument("--port", type=int, required=True)
    receiver.add_argument("--message", required=True)
    receiver.add_argument("--timeout", type=float, default=5.0)
    receiver.set_defaults(handler=receive)

    sender = subparsers.add_parser("send")
    sender.add_argument("--group", required=True)
    sender.add_argument("--interface", required=True)
    sender.add_argument("--port", type=int, required=True)
    sender.add_argument("--message", required=True)
    sender.set_defaults(handler=send)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
