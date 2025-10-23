#!/bin/bash

# CONFIG

LIBFABRIC=../../libfabric/src/.libs

CLI_IFACE=enp175s0f0np0
SRV_IFACE=enp175s0f0np0

CLI_IP=192.168.1.1
SRV_IP=192.168.1.2

CLI_SSI=2
SRV_SSI=1

# DON'T EDIT BEYOND THIS POINT

IS_CLI=
if [ "$1" = client ]; then
    IS_CLI=yes
elif [ "$1" != server ]; then
    echo "Usage: $0 <client|server> [<test>]"
    echo ""
    echo "  Default is to run ALL tests!"
    echo "    <test> = sng, pds, pds_direct, pds_cluster,"
    echo "             pds_cluster_ssi, pds_server_ssi"
    echo ""
    exit 1
fi

banner()
{
    echo ""
    echo "**************************************************************"
    echo "* --> ${1}"
    echo "**************************************************************"
    echo ""

    # sleep call is to give enough time for the server to start up
    if [ -n "$IS_CLI" ]; then
        sleep 1
    fi
}

CMD_CLI="LD_LIBRARY_PATH=${LIBFABRIC} UET_IFNAME=${CLI_IFACE} ./uet client"
CMD_SRV="LD_LIBRARY_PATH=${LIBFABRIC} UET_IFNAME=${SRV_IFACE} ./uet server"

tests=("" "tag" "rma")

function sng()
{
    EX_DEFS="UET_PDS=sng"
    for test in "${tests[@]}"; do
        banner "SNG $test"
        if [ -n "$IS_CLI" ]; then
            CMD="${CMD_CLI} $test ${SRV_IP}"
        else
            CMD="${CMD_SRV} $test ${CLI_IP}"
        fi
        CMD="sudo ${EX_DEFS} ${CMD}"
        echo $CMD; eval $CMD
    done
}

function pds()
{
    EX_DEFS="UET_PDS=pds"
    for test in "${tests[@]}"; do
        banner "PDS $test"
        if [ -n "$IS_CLI" ]; then
            CMD="${CMD_CLI} $test ${SRV_IP}"
        else
            CMD="${CMD_SRV} $test ${CLI_IP}"
        fi
        CMD="sudo ${EX_DEFS} ${CMD}"
        echo $CMD; eval $CMD
    done
}

function pds_direct()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=direct"
    for test in "${tests[@]}"; do
        banner "PDS w/ SEC=direct $test"
        if [ -n "$IS_CLI" ]; then
            CMD="${CMD_CLI} $test ${SRV_IP}"
        else
            CMD="${CMD_SRV} $test ${CLI_IP}"
        fi
        CMD="sudo ${EX_DEFS} ${CMD}"
        echo $CMD; eval $CMD
    done
}

function pds_cluster()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    for test in "${tests[@]}"; do
        banner "PDS w/ SEC=cluster $test"
        if [ -n "$IS_CLI" ]; then
            CMD="${CMD_CLI} $test ${SRV_IP}"
        else
            CMD="${CMD_SRV} $test ${CLI_IP}"
        fi
        CMD="sudo ${EX_DEFS} ${CMD}"
        echo $CMD; eval $CMD
    done
}

function pds_cluster_ssi()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=cluster"
    for test in "${tests[@]}"; do
        banner "PDS w/ SEC=cluster (SSI) $test"
        if [ -n "$IS_CLI" ]; then
            CMD="UET_SEC_SSI=${CLI_SSI} ${CMD_CLI} $test ${SRV_IP}"
        else
            CMD="UET_SEC_SSI=${SRV_SSI} ${CMD_SRV} $test ${CLI_IP}"
        fi
        CMD="sudo ${EX_DEFS} ${CMD}"
        echo $CMD; eval $CMD
    done
}

function pds_server_ssi()
{
    EX_DEFS="UET_PDS=pds UET_SEC_MODE=server"
    for test in "${tests[@]}"; do
        banner "PDS w/ SEC=server (SSI) $test"
        if [ -n "$IS_CLI" ]; then
            CMD="UET_SEC_SSI=${CLI_SSI} ${CMD_CLI} $test ${SRV_IP}"
        else
            CMD="UET_SEC_SSI=${SRV_SSI} UET_SEC_CLIENT_SSI=${CLI_SSI} ${CMD_SRV} $test ${CLI_IP}"
        fi
        CMD="sudo ${EX_DEFS} ${CMD}"
        echo $CMD; eval $CMD
    done
}

if [ -z "$2" -o "$2" = sng             ]; then sng;             fi
if [ -z "$2" -o "$2" = pds             ]; then pds;             fi
if [ -z "$2" -o "$2" = pds_direct      ]; then pds_direct;      fi
if [ -z "$2" -o "$2" = pds_cluster     ]; then pds_cluster;     fi
if [ -z "$2" -o "$2" = pds_cluster_ssi ]; then pds_cluster_ssi; fi
if [ -z "$2" -o "$2" = pds_server_ssi  ]; then pds_server_ssi;  fi

banner "Done!"

