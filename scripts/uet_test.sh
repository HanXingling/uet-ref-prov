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
test_names=(all rma rudi uud sync_rma atomic sync_atomic tag tag_any_src unexp_untag unexp_tag defer_send defer_tag defer_tag_any_src)
pds_names=(all sng pds pds_direct pds_cluster pds_cluster_ssi pds_server_ssi pds_cluster_key_rot pds_cluster_1rtt pds_cluster_churn pds_cluster_interop)
shim_names=(rawsock xdp)

# (not for sng) default ACK type: ack, ack_cc, ack_ccx
ACK_TYPE=ack_cc

# (not for sng) default Tx timeout (in millisecs) and max Tx retries.
# Security (TSS) runs use a longer timeout because the crypto path adds
# per-packet latency that can trip the aggressive default and cause
# spurious retransmits. Impairment-shim runs use a longer timeout still: the
# shim's userspace Tx queue/thread adds enough round-trip latency that the
# default RTO would fire on merely-slow (not lost) packets, causing a
# spurious-retransmit storm.
TX_TIMEOUT=5
TX_TIMEOUT_SEC=25
TX_TIMEOUT_IMP=100
MAX_TX_RETRIES=5

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

app_test=$test
FORCE_RUDI=""
FORCE_UUD=""
if [ "$test" = rudi ]; then
    # RUDI is a delivery mode, not a distinct app test. The 'rudi' test runs
    # the existing 'rma' write/read exchange but forces the RUDI delivery mode
    # via UET_FORCE_RUDI. It requires the 'pds' backend (sng rejects RUDI).
    app_test=rma
    FORCE_RUDI="UET_FORCE_RUDI=1"
elif [ "$test" = uud ]; then
    # UUD is a best-effort single-packet datagram send. The 'uud' app test
    # runs the untagged send exchange forcing the UUD delivery mode via
    # UET_FORCE_UUD. It requires the 'pds' backend (sng rejects UUD).
    FORCE_UUD="UET_FORCE_UUD=1"
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

IMP_SHIM=""
if [ -n "$UET_IMPAIRMENT_SHIM" ]; then
    IMP_SHIM="UET_IMPAIRMENT_SHIM=${UET_IMPAIRMENT_SHIM}"
fi

CMD_BASE="LD_LIBRARY_PATH=${LIBFABRIC}:. UET_IFNAME=${iface} UET_NIC_SHIM=${shim} UET_PDS_ACK_TYPE=${ACK_TYPE} UET_PDS_MAX_TX_RETRIES=${MAX_TX_RETRIES} ${FORCE_RUDI} ${FORCE_UUD} ${IMP_SHIM} ./${app_name}"

function run_test()
{
    # TSS runs (UET_SEC_MODE set) use a longer Tx timeout since the crypto
    # path adds per-packet latency. Impairment-shim runs use a longer one
    # still (shim queue/thread latency); it dominates, so check it last.
    local timeout=$TX_TIMEOUT

    if [[ "$1" == *UET_SEC_MODE* ]]; then
        timeout=$TX_TIMEOUT_SEC
    fi

    if [[ "$1" == *UET_IMPAIRMENT_SHIM* ]]; then
        timeout=$TX_TIMEOUT_IMP
    fi

    local cmd="UET_PDS_TX_TIMEOUT=$timeout $1"
    echo sudo $cmd
    eval sudo $cmd || { rc=$?; echo -e "\nERROR: Test failed!\n"; exit $rc; }
}

# When the full 'all' suite runs on a reliable PDS backend, also exercise
# the RUDI delivery mode. A forced RUDI RMA WRITE/READ pass used the
# RUDI PDS engine and an IDEMPOTENT_SAFE MR. This cannot be run using the
# sng backend.
function rudi_pass()
{
    [ "$test" = all ] || return 0
    banner "RUDI (forced) $1"
    run_test "$1 UET_FORCE_RUDI=1 $CMD_BASE $actor rma $peer_ip"
}

# When the full 'all' suite runs on a reliable PDS backend, also exercise the
# UUD delivery mode. A forced UUD single-packet best-effort datagram send. UUD
# needs the UUD PDS engine. This cannot be run using the sng backend.
function uud_pass()
{
    [ "$test" = all ] || return 0
    banner "UUD (forced) $1"
    run_test "$1 UET_FORCE_UUD=1 $CMD_BASE $actor uud $peer_ip"
}

function sng()
{
    UET_DEFS="UET_PDS=sng"
    banner "SNG $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
}

function pds()
{
    UET_DEFS="UET_PDS=pds"
    banner "PDS $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
    rudi_pass "$UET_DEFS"
    uud_pass "$UET_DEFS"
}

function pds_direct()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=direct"
    # IPv6 direct mode requires SSI
    if [ $is_ipv6 -eq 1 ]; then
        UET_DEFS="$UET_DEFS UET_SEC_SSI=$ssi"
    fi
    banner "PDS w/ SEC=direct $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
    rudi_pass "$UET_DEFS"
    uud_pass "$UET_DEFS"
}

function pds_cluster()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    banner "PDS w/ SEC=cluster $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
    rudi_pass "$UET_DEFS"
    uud_pass "$UET_DEFS"
}

# Long, wall-clock-sized cluster run with AN key rotation enabled. Both
# peers rotate keys off the shared wall clock (no SDME, no signaling), so no
# exchange is needed. Sized via UET_NUM_ITERATIONS to span several rotations
# and at least one key-pool wrap.
function pds_cluster_key_rot()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster UET_SEC_KEY_ROTATION=1 UET_NUM_ITERATIONS=800"
    banner "PDS w/ SEC=cluster + AN key rotation $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
}

# Secure PDC establishment via RANDOM_1RTT_START. All other PDS with crypto
# tests use 0-RTT by default. For 1-RTT, the target rejects the initiator's
# start PSN, NACKs a minted one, and the initiator restarts the establishment.
# Exercises the full round-trip establishment on every PDC.
function pds_cluster_1rtt()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster UET_PDS_PSN_METHOD=1rtt"
    banner "PDS w/ SEC=cluster + 1RTT establishment $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
}

# Secure 0RTT establishment under PDC churn. UET_PDC_CLOSE_THRESH randomly
# closes PDCs after message EOM, forcing re-establishment. Each close advances
# the SDI expected PSN on the target and returns it in the closing ACK. The
# initiator adopts it as the next start PSN so re-opened PDCs stay 0-RTT
# (no NACK) and old start PSNs are rejected.
function pds_cluster_churn()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster UET_PDC_CLOSE_THRESH=500"
    banner "PDS w/ SEC=cluster + PDC churn $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
}

# Cross-method secure PDS establishment interop. The two FEPs run DIFFERENT
# methods (client 0-RTT, server 1-RTT). A FEP's method only governs how it
# validates incoming SYNs as a target, so this exercises both flows at once.
#  - client->server: PDCs hit the server's 1-RTT mint/NACK/re-drive
#  - server->client: PDCs hit the client's 0-RTT acceptance check
function pds_cluster_interop()
{
    if [ "$actor" = client ]; then
        method=0rtt
    else
        method=1rtt
    fi
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster UET_PDS_PSN_METHOD=$method"
    banner "PDS w/ SEC=cluster + cross-method interop (cli=0rtt srv=1rtt) $test"
    run_test "$UET_DEFS $CMD_BASE $actor $app_test $peer_ip"
}

function pds_cluster_ssi()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    UET_SSI_DEFS="UET_SEC_SSI=$ssi"
    banner "PDS w/ SEC=cluster (SSI) $test"
    run_test "$UET_DEFS $UET_SSI_DEFS $CMD_BASE $actor $app_test $peer_ip"
    rudi_pass "$UET_DEFS $UET_SSI_DEFS"
    uud_pass "$UET_DEFS $UET_SSI_DEFS"
}

function pds_server_ssi()
{
    UET_DEFS="UET_PDS=pds UET_SEC_MODE=server"
    UET_SSI_DEFS="UET_SEC_SSI=$ssi UET_SEC_CLIENT_SSI=$CLI_SSI"
    banner "PDS w/ SEC=server (SSI) $test"
    run_test "$UET_DEFS $UET_SSI_DEFS $CMD_BASE $actor $app_test $peer_ip"
    rudi_pass "$UET_DEFS $UET_SSI_DEFS"
    uud_pass "$UET_DEFS $UET_SSI_DEFS"
}

if [ $pds = all -o $pds = sng             ]; then sng;                 fi
if [ $pds = all -o $pds = pds             ]; then pds;                 fi
if [ $pds = all -o $pds = pds_direct      ]; then pds_direct;          fi
if [ $pds = all -o $pds = pds_cluster     ]; then pds_cluster;         fi
if [ $pds = all -o $pds = pds_cluster_ssi ]; then pds_cluster_ssi;     fi
if [ $pds = all -o $pds = pds_server_ssi  ]; then pds_server_ssi;      fi
if [ $pds = pds_cluster_key_rot           ]; then pds_cluster_key_rot; fi
if [ $pds = pds_cluster_1rtt              ]; then pds_cluster_1rtt;    fi
if [ $pds = pds_cluster_churn             ]; then pds_cluster_churn;   fi
if [ $pds = pds_cluster_interop           ]; then pds_cluster_interop; fi

banner "Done!"

