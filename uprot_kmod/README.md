---
created: 2025-11-03T19:40
updated: 2025-11-05T08:56
---

# User Protocol Linux RDMA Driver (`uprot`)

The `uprot` kernel module implements a minimal RDMA driver that enables the following:
- Device enumeration by `rdma-core` when `ibv_get_device_list()` is called.
- Driver and device attachment of the `uprot` provider driver in `rdma-core` when `ibv_open_device()` is called.
- Support for allocating and destroying User Context structures.
- Support for allocating and destroying Protection Domains (PDs).
- Support for managing the SGID table and exposing available source addresses.

This kernel module does NOT support any `uverbs` `ioctl` commands to allocate and manage other resources (i.e., QPs, CQs, MRs, etc). The `uprot` provider driver will manage all of these resources within itself since the transport used for the `uprot` device is implemented solely in userspace.

> [!note]
> The `uprot` kernel module is a heavily stripped down version of the `rxe`
> driver. If additional functionality is required in `uprot`, leverage the
> existing code found in `rxe`.

## Required Packages

- **Kernel headers**: Matching your running kernel version
- **Build tools**: gcc, make, and other standard build utilities

```bash
% sudo apt-get update
% sudo apt-get install build-essential linux-headers-$(uname -r)
```

Using this kernel module requires a version of `rdma-core` that contains the associated `uprot` provider driver that can attach to this module.

## Building the Module

To compile the kernel module and produce the `rdma_uprot.ko` binary:

```bash
% cd /path/to/uprot_kmod
% make
```

## Loading the Module

To load the kernel module and verify it has been loaded:

```bash
% sudo modprobe ./rdma_uprot.ko
% lsmod | grep rdma_uprot
```

## Check Kernel Messages

The `rdma_uprot.ko` kernel module prints out various debug information to the kernel log.

```bash
% sudo dmesg -w
```

## Create an RDMA Device

After loading the module, you need to use the `rdma` command to create an RDMA device and link it to an existing network interface.

```bash
% ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:a5:e5:e6 brd ff:ff:ff:ff:ff:ff
    altname enp2s0
    inet 172.16.71.133/24 brd 172.16.71.255 scope global dynamic noprefixroute ens160
       valid_lft 979sec preferred_lft 979sec
    inet6 fe80::e35b:f800:374a:e32a/64 scope link noprefixroute
       valid_lft forever preferred_lft forever

% sudo rdma link add uprot0 type uprot netdev ens160
```

## Get RDMA Device Information

Use any of the `rdma`, `ibv_devices`, or `ibv_devinfo` commands to query the system and verify the status of the `uprot0` device.

```bash
% rdma link show
link uprot0/1 state ACTIVE physical_state LINK_UP netdev ens160
```

```bash
% ibv_devices
    device                 node GUID
    ------              ----------------
    uprot0              020c29fffea5e5e6
```

```bash
% ibv_devinfo -v
hca_id: uprot0
        transport:                      InfiniBand (0)
        fw_ver:                         0.0.0
        node_guid:                      020c:29ff:fea5:e5e6
        sys_image_guid:                 020c:29ff:fea5:e5e6
        vendor_id:                      0xffffff
        vendor_part_id:                 0
        hw_ver:                         0x0
        phys_port_cnt:                  1
        max_mr_size:                    0xffffffffffffffff
        page_size_cap:                  0xfffff000
        max_qp:                         1048560
        max_qp_wr:                      1048576
        device_cap_flags:               0x01223c76
                                        BAD_PKEY_CNTR
                                        BAD_QKEY_CNTR
                                        AUTO_PATH_MIG
                                        CHANGE_PHY_PORT
                                        UD_AV_PORT_ENFORCE
                                        PORT_ACTIVE_EVENT
                                        SYS_IMAGE_GUID
                                        RC_RNR_NAK_GEN
                                        SRQ_RESIZE
                                        MEM_WINDOW
                                        MEM_MGT_EXTENSIONS
                                        MEM_WINDOW_TYPE_2B
        max_sge:                        32
        max_sge_rd:                     32
        max_cq:                         1048576
        max_cqe:                        32767
        max_mr:                         524287
        max_pd:                         1048576
        max_qp_rd_atom:                 128
        max_ee_rd_atom:                 0
        max_res_rd_atom:                258048
        max_qp_init_rd_atom:            128
        max_ee_init_rd_atom:            0
        atomic_cap:                     ATOMIC_HCA (1)
        max_ee:                         0
        max_rdd:                        0
        max_mw:                         524287
        max_raw_ipv6_qp:                0
        max_raw_ethy_qp:                0
        max_mcast_grp:                  8192
        max_mcast_qp_attach:            56
        max_total_mcast_qp_attach:      458752
        max_ah:                         32767
        max_fmr:                        0
        max_srq:                        917503
        max_srq_wr:                     1048576
        max_srq_sge:                    27
        max_pkeys:                      64
        local_ca_ack_delay:             15
        general_odp_caps:
        rc_odp_caps:
                                        NO SUPPORT
        uc_odp_caps:
                                        NO SUPPORT
        ud_odp_caps:
                                        NO SUPPORT
        xrc_odp_caps:
                                        NO SUPPORT
        completion_timestamp_mask not supported
        core clock not supported
        device_cap_flags_ex:            0x1C001223C76
                                        Unknown flags: 0x1C000000000
        tso_caps:
                max_tso:                        0
        rss_caps:
                max_rwq_indirection_tables:                     0
                max_rwq_indirection_table_size:                 0
                rx_hash_function:                               0x0
                rx_hash_fields_mask:                            0x0
        max_wq_type_rq:                 0
        packet_pacing_caps:
                qp_rate_limit_min:      0kbps
                qp_rate_limit_max:      0kbps
        tag matching not supported
        num_comp_vectors:               2
                port:   1
                        state:                  PORT_ACTIVE (4)
                        max_mtu:                4096 (5)
                        active_mtu:             1024 (3)
                        sm_lid:                 0
                        port_lid:               0
                        port_lmc:               0x00
                        link_layer:             Ethernet
                        max_msg_sz:             0x800000
                        port_cap_flags:         0x00000000
                        port_cap_flags2:        0x0000
                        max_vl_num:             1 (1)
                        bad_pkey_cntr:          0x0
                        qkey_viol_cntr:         0x0
                        sm_sl:                  0
                        pkey_tbl_len:           1
                        gid_tbl_len:            1024
                        subnet_timeout:         0
                        init_type_reply:        0
                        active_width:           1X (1)
                        active_speed:           2.5 Gbps (1)
                        phys_state:             LINK_UP (5)
                        GID[  0]:               fe80::20c:29ff:fea5:e5e6, RoCE v2
                        GID[  1]:               ::ffff:172.16.71.133, RoCE v2
                        GID[  2]:               fe80::e35b:f800:374a:e32a, RoCE v2
```

## Unloading the Module

```bash
sudo rdma link delete uprot0
sudo rmmod rdma_uprot
```

