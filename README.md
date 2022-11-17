# Breach &amp; Attack Software on a Software-Defined Network

Breach &amp; Attack Software (aka. Adversary Simulation) simulated on 
Containernet, a Docker-compatible fork of mininet. Utlises the Containernet
Python API to generate a simulated network with both normal and vulnerable
hosts, one data collector (for network traffic), and the Infection Monkey
'island' host.

## Requirements

The following packages are required for the given python application to work 
correctly:

 - **Ubuntu 20.04** (due to `containernet` compatibility)
 - **Docker CE** (https://docs.docker.com/engine/install/debian/)
 - **Containernet** (https://github.com/containernet/containernet)
 - **Python 3.8+**
 - **Infection Monkey AppImage** (saved in `infectionmonkey_d/`) (https://github.com/guardicore/monkey)

 Python requirements are documented in the requirements.txt file.
 
 **NOTE:** Mininet Python modules are provided by `containernet`.

## Usage
```plaintext
bassdn.py [-h] [-n N_HOSTS] [-v V_HOSTS] [-s SEGMENTS] [--network-range NETWORK_RANGE]

Launches a software-defined network with vulnerable and non-vulnerable hosts
as well as one Infection Monkey instance.

optional arguments:
  -h, --help            show this help message and exit
  -n N_HOSTS, --n-hosts N_HOSTS
                        Number of regular (non-vulnerable) hosts to deploy
                        (default: 4)
  -v V_HOSTS, --v-hosts V_HOSTS
                        Number of vulnerable hosts to deploy
                        (default: 4)
  -s SEGMENTS, --segments SEGMENTS
                        Number of network segments (i.e. switches) to deploy
                        (default: 1)
  --network-range NETWORK_RANGE
                        CIDR IP range that the network will operate in
                        (default: 10.0.0.0/24)
```
