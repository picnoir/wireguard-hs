
**nara** is a userspace implementation of [WireGuard](https://www.wireguard.io),
a fast, modern and secure VPN based on [Noise](https://noiseprotocol.org/) protocol.

### Build

Only Linux and macOS are supported at this moment.

To build **nara**, download and install [haskell-stack](https://github.com/commercialhaskell/stack) first.
~~~
$ stack setup
$ stack install
~~~

### Usage

The following command will create a TUN device named `wg0` and then daemonize
to background.
~~~
# nara wg0
~~~

After that, use the usual `wg` tool to configure the device. For most
distributions it's in the `wireguard-tools` package. Check the manpage
of `wg` for details.

### Status

Currently this is just a prototype, and there are still a lot to be done.

- [ ] Documents and test coverage
- [ ] Receiver-side nonce deduplicate
- [ ] Logging and better exceptions handling
- [ ] Cookie support to prevent DDOS attack
- [ ] Full IPv6 support
- [ ] An accurate timer based approach to manage lifetimes
- [ ] Send ICMP packets back in case of unreachable hosts
- [ ] Persistent-keepalive
- [ ] Per-host packet queue
- [ ] Benchmark, and performance optimization
- [ ] FreeBSD support (perhaps Windows support as well)
- [ ] MTU discovery and setting

### License

This software is licensed in GPLv3+.
