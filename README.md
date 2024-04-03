
# UEC Reference Provider (libfabric)

This repository provides a reference implementation of the UEC transport
specifications including:
- Semantic Sublayer (SES)
- Packet Delivery Sublayer (PDS) - Reliability and Congestion Management
- Security

See SDR4001 and the UEC Libfabric Mapping Specification for additional details.

## Goals

- Reference implementation of the libfabric mapping, semantic, packet delivery, and security layers
- Investigate lower-level interfaces in libfabric (memory management)
- Provide a framework to define Linux kernel interfaces (i.e., netlink)
- Development/integration vehicle for higher level libraries (i.e, xCCL)
- User and kernel mode integration options
- Clarity and feature coverage is more important than performance
- Minimal external dependencies

## Overview

The framework for the UET Reference Provider is layered. The layers include
SES, PDS, Security, and NIC.

The SES layer is accessed via UET APIs (see uet_api.h)

SES interfaces with PDS via SES-PDS APIs (see uet_pds.h)

The NIC shim interface is accessed via a set of abstracted APIs (see
uet_nic.h).

The current SES implementation supports a subset of the functionality required
for:
- Sending and receiving both untagged and tagged messages
- RMA write operations
 
This is a work-in-progress and additional functionality will be incrementally
added.

## Status

The current PDS implementation is a placeholder. It is not an implementation of
the UET PDS Specification. It implements a simple stop-and-wait ROD transport
that is sufficient to enable development of other layers. The current PDS
implementation will be replaced with a "real" implementation of the UET PDS
specification.

There are currently two implementations of the NIC shim interface APIs:
- Raw Ethernet socket
- AF_XDP

Testing is performed using a simple top-level program that performs ping-pong
message data transfer operations between a client and a server (see uet.c).

### Congestion Control

A partial implementation of UET Network Signal Congestion Control (NSCC), based on the
v0.6 specification, can be found in the `cc` subdirectory. Multi-path packet delivery
is not fully supported.

The CC algorithm can be tested separately with a basic test app, which simulates multiple senders
transmitting to a single receiver. Packets can be dropped, ECN marked or trimmed.
The application measures the throughput achieved by each sender, to verify that the CC algorithm
enables high bandwidth utilization and fair sharing among the senders.
The app runs on a single machine and does not generate network traffic. The sources are
located in the `cc_sim` subdirectory.

## Preparation

Make sure the proper development libraries/headers are installed:
```
% sudo apt install linux-headers-$(uname -r)
% sudo apt install gcc gcc-multilib clang libbpf-dev libxdp-dev
```

## libfabric

- https://github.com/ofiwg/libfabric/releases

Download and build libfabric in the parent directory. Any version can be used
as long as the directory name is just `libfabric`. The steps below build
libfabric v1.20.1 and uses a symlink for the common name.

```
% cd ..
% wget https://github.com/ofiwg/libfabric/releases/download/v1.20.1/libfabric-1.20.1.tar.bz2
% tar -jxvf libfabric-1.20.1.tar.bz2
% ln -s libfabric-1.20.1 libfabric
% cd libfabric
% autoreconf    # might be needed depending on the system
% ./configure
% make -j
```

## Build and Run

### rawsock

> The `uet` program only has the `rawsock` NIC shim built into it.

```
% make

# server...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs UET_IFNAME=ens4f0np0 ./uet server 192.168.1.2

# client...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs UET_IFNAME=ens4f0np0 ./uet client 192.168.1.1
```

### xdp

> The `uet_xdp` program has both `rawsock` and `xdp` build into it and the
> default NIC shim is `xdp`. The `UET_NIC_SHIM` environment variable can be
> used to override the default.

The current XDP implementation performs a copy to/from the XDP umem Tx/Fill
packet buffers. This interface will be enhanced to eliminate the copy.

The eBPF program loaded for the UET XDP interface only picks out packets with
Ethernet protocol number 253. All other packets are sent to the Linux network
stack so traditional L2 traffic (i.e., ARP, SSH, etc) will continue to flow
over the interface.

```
% make xdp

# server...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs UET_IFNAME=ens4f0np0 ./uet_xdp server 192.168.1.2

# client...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs UET_IFNAME=ens4f0np0 ./uet_xdp client 192.168.1.1
```

### CC tester

Simulation parameters (link speed, RTT, queue size, drop thresholds etc.) can be set by modifying
the main function located in `cc_sim/sim.c`.

```
% make uet_cc_sim
% LD_LIBRARY_PATH=../libfabric/src/.libs ./uet_cc_sim 2
```

Replace `2` with the desired number of senders.

## Environment Variables

- **LD_LIBRARY_PATH** - Needed for dynamic linking to libfabric library.
- **UET_IFNAME** - The ifname of the interface to attach to.
- **UET_NIC_SHIM** - [ `rawsock` | `xdp` ]
- **UET_PDS** - [ `sng` ] (default=`sng` stop-n-go)

## XDP

Use `UET_NIC_SHIM=xdp` to send/receive packets over XDP.

Make sure the underlying NIC interface (i.e., `UET_IFNAME`) uses only a single
queue. The current XDP implementation does not yet support multiple sockets.

```
% sudo ethtool -L ens4f0np0 combined 1
```

Use `xdp-loader` to check if an XDP program is loaded and attached to the
interface. If the UET application was killed ungracefully, the XDP program
could remain attached. Use `xdp-loader` to unload any XDP programs.

```
% sudo xdp-loader status
% sudo xdp-loader unload --all ens4f0np0
```

## Contributing

Code changes, fixes, enhancements, etc are encouraged and greatly welcome!

Please submit a
[pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests)
to be reviewed before being merged into the master branch.

The source code in this repo follows the Linux kernel coding style. Before
submitting changes, please run the modified files using the Linux kernel
`checkpatch.pl` script:
- All ERRORs must be fixed.
- All WARNINGs should be fixed if possible (use discretion).
- https://docs.kernel.org/dev-tools/checkpatch.html
- https://raw.githubusercontent.com/torvalds/linux/master/scripts/checkpatch.pl

Running `checkpatch.pl` out of tree against a local `.h` or `.c` file:
```
% ~/checkpatch.pl --no-tree -f uet_api.h
```

Thank you! 😀

