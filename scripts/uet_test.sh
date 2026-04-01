#!/bin/bash

# SSI values used for security tests
CLI_SSI=2
SRV_SSI=1

# Auto-discover libfabric directory by searching up parent directories
LIBFABRIC=""
current_dir="$(pwd)"
while [ "$current_dir" != "/" ]; do
    for dir in "$current_dir"/libfabric*; do
        if [ -d "$dir/src/.libs" ]; then
            LIBFABRIC="$dir/src/.libs"
            echo "Found libfabric directory: $LIBFABRIC"
            break 2
        fi
    done
    current_dir="$(dirname "$current_dir")"
done

if [ -z "$LIBFABRIC" ]; then
    echo "ERROR: libfabric directory not found"
    exit 1
fi

# Valid "test", "pds", and "shim" names
test_names=(all rma sync_rma atomic sync_atomic tag tag_any_src unexp_untag unexp_tag defer_send defer_tag defer_tag_any_src)
pds_names=(all sng pds pds_direct pds_cluster pds_cluster_ssi pds_server_ssi)
shim_names=(rawsock xdp)

function usage()
{
    echo "Usage: $0 <client|server> <ifname> <peer_ip> <test> <pds> [ <shim> ]"
    echo ""
    echo -e "\t<client|server>: role to run as"
    echo -e "\t<ifname>: local network interface name"
    echo -e "\t<peer_ip>: IP address of the peer"
    echo ""
    echo -e "\t<test>:"
    for t in "${test_names[@]}"; do
        echo -e "\t\t$t"
    done
    echo ""
    echo -e "\t<pds>:"
    for p in "${pds_names[@]}"; do
        echo -e "\t\t$p"
    done
    echo ""
    echo -e "\t<shim>: (optional, default: rawsock)"
    for s in "${shim_names[@]}"; do
        echo -e "\t\t$s"
    done
    echo ""
    exit 1
}

if [ "$1" = client ]; then
    actor=client
    ssi=$CLI_SSI
elif [ "$1" = server ]; then
    actor=server
    ssi=$SRV_SSI
else
    echo "ERROR: must specify client or server"
    usage
fi

# Parse command line arguments
iface=$2
peer_ip=$3
test=$4
pds=$5

if [ -z "$iface" ]; then
    echo "ERROR: interface name required"
    usage
fi

if [ -z "$peer_ip" ]; then
    echo "ERROR: peer IP address required"
    usage
fi

# Detect IPv6 (contains colon)
is_ipv6=0
if [[ "$peer_ip" == *:* ]]; then
    is_ipv6=1
fi

# Validate test name
valid_test=0
for t in "${test_names[@]}"; do
    if [ "$test" = "$t" ]; then
        valid_test=1
        break
    fi
done
if [ $valid_test -eq 0 ]; then
    echo "ERROR: Invalid test name"
    usage
fi

# Validate PDS name
valid_pds=0
for p in "${pds_names[@]}"; do
    if [ "$pds" = "$p" ]; then
        valid_pds=1
        break
    fi
done
if [ $valid_pds -eq 0 ]; then
    echo "ERROR: Invalid PDS name"
    usage
fi

# Parse optional shim argument (default: rawsock)
shim=${6:-rawsock}

# Validate shim name
valid_shim=0
for s in "${shim_names[@]}"; do
    if [ "$shim" = "$s" ]; then
        valid_shim=1
        break
    fi
done
if [ $valid_shim -eq 0 ]; then
    echo "ERROR: Invalid shim name"
    usage
fi

banner()
{
    echo ""
    echo "**************************************************************"
    echo "* --> ${1}"
    echo "**************************************************************"
    echo ""
}

# Set application name based on shim
if [ "$shim" = "xdp" ]; then
    app_name="uet_xdp"
else
    app_name="uet"
fi

CMD_BASE="LD_LIBRARY_PATH=${LIBFABRIC}:. UET_IFNAME=${iface} UET_NIC_SHIM=${shim} ./${app_name}"

function run_test()
{
    echo sudo $1
    eval sudo $1 || { rc=$?; echo -e "\nERROR: Test failed!\n"; exit $rc; }
}

function sng()
{
    UET_DEFS="UET_PDS=sng"
    banner "SNG $test"
    run_test "$UET_DEFS $CMD_BASE $actor $test $peer_ip"
}

function pds()
{
    UET_DEFS="UET_PDS=pds"
    banner "PDS $test"
    run_test "$UET_DEFS $CMD_BASE $actor $test $peer_ip"
}

function pds_direct()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=direct"
    # IPv6 direct mode requires SSI
    if [ $is_ipv6 -eq 1 ]; then
        UET_DEFS="$UET_DEFS UET_SEC_SSI=$ssi"
    fi
    banner "PDS w/ SEC=direct $test"
    run_test "$UET_DEFS $CMD_BASE $actor $test $peer_ip"
}

function pds_cluster()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    banner "PDS w/ SEC=cluster $test"
    run_test "$UET_DEFS $CMD_BASE $actor $test $peer_ip"
}

function pds_cluster_ssi()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    UET_SSI_DEFS="UET_SEC_SSI=$ssi"
    banner "PDS w/ SEC=cluster (SSI) $test"
    run_test "$UET_DEFS $UET_SSI_DEFS $CMD_BASE $actor $test $peer_ip"
}

function pds_server_ssi()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=server"
    UET_SSI_DEFS="UET_SEC_SSI=$ssi UET_SEC_CLIENT_SSI=$CLI_SSI"
    banner "PDS w/ SEC=server (SSI) $test"
    run_test "$UET_DEFS $UET_SSI_DEFS $CMD_BASE $actor $test $peer_ip"
}

if [ $pds = all -o $pds = sng             ]; then sng;             fi
if [ $pds = all -o $pds = pds             ]; then pds;             fi
if [ $pds = all -o $pds = pds_direct      ]; then pds_direct;      fi
if [ $pds = all -o $pds = pds_cluster     ]; then pds_cluster;     fi
if [ $pds = all -o $pds = pds_cluster_ssi ]; then pds_cluster_ssi; fi
if [ $pds = all -o $pds = pds_server_ssi  ]; then pds_server_ssi;  fi

banner "Done!"

