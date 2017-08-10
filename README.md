[![Travis Status](https://travis-ci.org/NinjaTrappeur/wireguard-hs.svg?branch=RPC-Refactoring)](https://travis-ci.org/NinjaTrappeur/wireguard-hs)
### Do not use this Haskell code.

This is not a complete implementation of WireGuard. If you're interested in using WireGuard, use the implementation for Linux [found here](https://git.zx2c4.com/WireGuard/) and described on the [main wireguard website](https://www.wireguard.io/). There is no group of users that should be using the code in this repository here under any circumstances at the moment, not even beta testers or dare devils. It simply isn't complete. However, if you're interested in assisting with the Haskell development of WireGuard and contributing to this repository, by all means dig in and help out. But users: stay far away, at least for now.

-----

**nara** is a userspace implementation of [WireGuard](https://www.wireguard.io),
a fast, modern and secure VPN based on [Noise](https://noiseprotocol.org/) protocol.

### Build

Only Linux and macOS are supported at this moment.

To build **nara**, download and install [haskell-stack](https://www.haskellstack.org) first.
~~~
$ stack setup   # This will download and install GHC in a sandboxed environment,
                # optional if stack has been configured to use global GHC.
$ stack install
~~~

### Usage

The following command will create a TUN device named `wg0` and then daemonize
to background. On macOS, the device name has to be like `utun1` or `utun2`.
Root privilege is also required.
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
