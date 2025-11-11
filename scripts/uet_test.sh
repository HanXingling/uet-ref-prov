#!/bin/bash

# CONFIG

LIBFABRIC=../libfabric/src/.libs

CLI_IFACE=enp175s0f0np0
SRV_IFACE=enp175s0f0np0

CLI_IP=192.168.1.1
SRV_IP=192.168.1.2

CLI_SSI=2
SRV_SSI=1

# DON'T EDIT BEYOND THIS POINT

function usage()
{
    echo "Usage: $0 <client|server> <test> [<pds>]"
    echo ""
    echo "   <test> = all"
    echo "            rma"
    echo "            tag"
    echo "            tag_any_src"
    echo "            unexp_untag"
    echo "            unexp_tag"
    echo "            defer_send"
    echo "            defer_tag"
    echo "            defer_tag_any_src"
    echo ""
    echo "    <pds> = all"
    echo "            sng"
    echo "            pds"
    echo "            pds_direct"
    echo "            pds_cluster"
    echo "            pds_cluster_ssi"
    echo "            pds_server_ssi"
    echo ""
    exit 1
}

IS_CLI=
if [ "$1" = client ]; then
    IS_CLI=yes
elif [ "$1" != server ]; then
    echo "ERROR: must specify client or server"
    usage
fi

if [ "$2" != all -a \
     "$2" != rma -a \
     "$2" != tag -a \
     "$2" != tag_any_src -a \
     "$2" != unexp_untag -a \
     "$2" != unexp_tag -a \
     "$2" != defer_send -a \
     "$2" != defer_tag -a \
     "$2" != defer_tag_any_src ]; then
    echo "ERROR: Invalid test name"
    usage
fi

if [ "$3" != all -a \
     "$3" != sng -a \
     "$3" != pds -a \
     "$3" != pds_direct -a \
     "$3" != pds_cluster -a \
     "$3" != pds_cluster_ssi -a \
     "$3" != pds_server_ssi ]; then
    echo "ERROR: Invalid PDS name"
    usage
fi

test=$2

banner()
{
    echo ""
    echo "**************************************************************"
    echo "* --> ${1}"
    echo "**************************************************************"
    echo ""
}

CMD_CLI="LD_LIBRARY_PATH=${LIBFABRIC}:. UET_IFNAME=${CLI_IFACE} ./uet client"
CMD_SRV="LD_LIBRARY_PATH=${LIBFABRIC}:. UET_IFNAME=${SRV_IFACE} ./uet server"

function sng()
{
    EX_DEFS="UET_PDS=sng"
    banner "SNG $test"
    if [ -n "$IS_CLI" ]; then
        CMD="${CMD_CLI} $test ${SRV_IP}"
    else
        CMD="${CMD_SRV} $test ${CLI_IP}"
    fi
    CMD="sudo ${EX_DEFS} ${CMD}"
    echo $CMD; eval $CMD
}

function pds()
{
    EX_DEFS="UET_PDS=pds"
    banner "PDS $test"
    if [ -n "$IS_CLI" ]; then
        CMD="${CMD_CLI} $test ${SRV_IP}"
    else
        CMD="${CMD_SRV} $test ${CLI_IP}"
    fi
    CMD="sudo ${EX_DEFS} ${CMD}"
    echo $CMD; eval $CMD
}

function pds_direct()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=direct"
    banner "PDS w/ SEC=direct $test"
    if [ -n "$IS_CLI" ]; then
        CMD="${CMD_CLI} $test ${SRV_IP}"
    else
        CMD="${CMD_SRV} $test ${CLI_IP}"
    fi
    CMD="sudo ${EX_DEFS} ${CMD}"
    echo $CMD; eval $CMD
}

function pds_cluster()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    banner "PDS w/ SEC=cluster $test"
    if [ -n "$IS_CLI" ]; then
        CMD="${CMD_CLI} $test ${SRV_IP}"
    else
        CMD="${CMD_SRV} $test ${CLI_IP}"
    fi
    CMD="sudo ${EX_DEFS} ${CMD}"
    echo $CMD; eval $CMD
}

function pds_cluster_ssi()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    banner "PDS w/ SEC=cluster (SSI) $test"
    if [ -n "$IS_CLI" ]; then
        CMD="UET_SEC_SSI=${CLI_SSI} ${CMD_CLI} $test ${SRV_IP}"
    else
        CMD="UET_SEC_SSI=${SRV_SSI} ${CMD_SRV} $test ${CLI_IP}"
    fi
    CMD="sudo ${EX_DEFS} ${CMD}"
    echo $CMD; eval $CMD
}

function pds_server_ssi()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=server"
    banner "PDS w/ SEC=server (SSI) $test"
    if [ -n "$IS_CLI" ]; then
        CMD="UET_SEC_SSI=${CLI_SSI} ${CMD_CLI} $test ${SRV_IP}"
    else
        CMD="UET_SEC_SSI=${SRV_SSI} UET_SEC_CLIENT_SSI=${CLI_SSI} ${CMD_SRV} $test ${CLI_IP}"
    fi
    CMD="sudo ${EX_DEFS} ${CMD}"
    echo $CMD; eval $CMD
}

if [ "$3" = all -o "$3" = sng             ]; then sng;             fi
if [ "$3" = all -o "$3" = pds             ]; then pds;             fi
if [ "$3" = all -o "$3" = pds_direct      ]; then pds_direct;      fi
if [ "$3" = all -o "$3" = pds_cluster     ]; then pds_cluster;     fi
if [ "$3" = all -o "$3" = pds_cluster_ssi ]; then pds_cluster_ssi; fi
if [ "$3" = all -o "$3" = pds_server_ssi  ]; then pds_server_ssi;  fi

banner "Done!"

