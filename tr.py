#!/usrcommitthon

import socket
import struct
import sys
import random
from optparse import OptionParser


def main(dst_name, port, hop_count):

    # Define TTL, UDP and ICMP.
    ttl = 1  # Initial TTL value, which will be incremented with each hop
    udp = socket.getprotobyname('udp')
    icmp = socket.getprotobyname('icmp')

    # Convert hostname to ip address.
    dst_addr = socket.gethostbyname(dst_name)

    while True:
        # Create sender and receiver. Sender uses UDP, receiver uses IDMP.
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)


        # Assign TTL to sender, increment TTL
        sender_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # Build the GNU timeval struct (seconds, microseconds)
        timeout = struct.pack('ll', 1, 0)

        # Set the receive timeout so we behave more like regular traceroute
        receiver_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

        # Bind socket and send message from sender to receiver.
        sender_socket.sendto("", (dst_name, port))
        receiver_socket.bind(("", port))

        curr_name = None
        curr_addr = None

        try:
            # Reads an array of 512-byte sized blocks from sender into curr_addr
            (_, curr_addr) = receiver_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]

            # Process socket errors
            except socket.error:
                curr_name = curr_addr

        except socket.error:
            pass
        finally:
            # Close both sockets
            sender_socket.close()
            receiver_socket.close()

        if curr_addr is not None:
            curr_host = '%s (%s)' % (curr_name, curr_addr)
        else:
            curr_host = "* * *"
        print('%d\t%s' % (ttl, curr_host))

        ttl += 1
        if curr_addr == dst_addr or ttl > hop_count:
            break


if __name__ == '__main__':

    default_port = random.choice(range(33434, 33535))
    default_max_hops = 7

    # Help and command-line options
    parser = OptionParser('tr - print the route packets trace to network host')

    parser.add_option('-p', '--port', dest='port',
                      help='Port to use for socket connection [default: %default]',
                      default=default_port, metavar='PORT')
    parser.add_option('-m', '--max-hops', dest='max_hops',
                      help='Max hops before giving up [default: %default]',
                      default=default_max_hops, metavar='MAXHOPS')

    (options, args) = parser.parse_args()

    # Check for valid agreement exist
    if len(args) == 0:
        parser.error('Please add destination address. (eg. tr.py google.com)')
    else:
        dest_name = args[0]
    sys.exit(main(dst_name=dest_name,
                  port=int(options.port),
                  hop_count=int(options.max_hops)))