# uet-ref-prov Sanity Check Workflow

This GitHub Actions workflow sets up a virtual bridge and VETH (virtual Ethernet) 
interfaces to run sanity tests and validate updates to `uet-ref-prov` on a single machine.


## Workflow Trigger

The workflow is triggered by:
- Push events
- Pull requests on the current branch

## jobs

### run_sanity

This job runs on an `ubuntu-latest` GitHub-hosted runner and follows these steps:

#### Check out the code

Uses the `actions/checkout@v3` action to check out the code from the repository. 
This makes the repository code available to the workflow for modification and testing.

#### Install bridge-utils

Installs necessary networking tools:

- `iproute2`: Manages network devices and routes.
- `bridge-utils`: Configures and manages network bridges.


####  Create VETH Interfaces

- Creates two virtual Ethernet interfaces:
  - `vm1`: Virtual interface connected to `vm2`.
  - `vm2`: Peer interface for `vm1`.
- Activates `vm1` by setting it up

#### Create the Bridge

Adds a tap device named `tapm` for virtual machine bridging and brings it up.
Creates a bridge named `brm`.

#### Bring the Bridge Up

- Connects the `tapm` and `vm1` interfaces to the `brm` bridge.
- Assigns IP addresses:
    - `brm`: `10.1.0.1`
    - `vm2`: `10.1.0.2`
- Brings up `brm` and `vm2`.

#### Bring the libfabric Up

Downloads, extracts, and compiles the libfabric library.

####  Compile uet-ref-prov

Compiles the `uet-ref-prov`.

#### Check Network Connectivity (brm to vm2)

Verifies network communication from the `brm` to `vm2`.

#### Check Network Connectivity (vm2 to brm)

Verifies network communication from the `vm2` to `brm`.

#### Add IP Addresses to the ARP Table

Fetches the MAC addresses of `brm` and `vm2`, then adds static entries to the ARP tables 
to bind IPs with their respective MAC addresses.

#### Start Server and Client

Runs sanity tests on uet-ref-prov to validate updates. Multithreading is unnecessary 
as the server runs in the background, and the client starts two seconds later.

