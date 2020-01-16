# SMOL DHCPD

A small DHCP client written in C. It runs a DHCPDiscover, waits for the DHCPOffer, obtains the lease via DHCPRequest and then releases it with DHCPRelease though can be extended to run fully and capture leases as a proper daemon. Written for Linux RAW sockets. Written to test DHCP servers.

## To build

- Run `make all` and run the binary.
