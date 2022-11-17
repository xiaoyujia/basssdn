#!/usr/bin/python3
import inspect
import defopt
import socket
import os

from enum import Enum
from rich import inspect
from mininet.cli import CLI
from datetime import datetime
from rich.console import Console
from ipaddress import IPv4Network
from mininet.node import Controller
from mininet.net import Containernet

console = Console()

class Host(Enum):
    HOST_NORMAL = 0
    HOST_VULNERABLE = 1
    HOST_INFECTIONMONKEY = 2
    HOST_COLLECTOR = 3

class BASSDN():
    def __init__(self, network_range='10.0.0.0/24'):
        self.net = Containernet(controller=Controller)
        self.net.addController('c0')
        self.hosts = []
        self.switches = []
        self.links = []

        # network range used to keep track of assigned IP addresses.
        self.netrange = IPv4Network(network_range)
        self.netrange_iterator = (host for host in self.netrange.hosts())

        # create a list for each host type
        for type in (Host):
            self.hosts.append([])

    def addHost(self, host_type: Host):
        """
        Adds a Docker host to the running network. Hosts are given a name of 
        either `normX` (for normal), `vulnX` (for vulnerable), `monkX` (for 
        monkey), and `collX` (for a collector). Hosts start at index `0` 
        (i.e., `norm0`) and increase by one for each host of that type created.
        """
        ip = next(self.netrange_iterator).__str__()
        hostname = ""

        if host_type == Host.HOST_NORMAL:
            hostname = f"norm{self.hosts[host_type.value].__len__()}"
            self.hosts[host_type.value].append(
                self.net.addDocker(
                    name=hostname,
                    ip=ip,
                    dimage='normal'
                )
            )
        elif host_type == Host.HOST_VULNERABLE:
            hostname = f"vuln{self.hosts[host_type.value].__len__()}"
            self.hosts[host_type.value].append(
                self.net.addDocker(
                    name=hostname,
                    ip=ip,
                    dimage='vulnerable',
                    dcmd='/usr/sbin/sshd -D'
                )
            )
        elif host_type == Host.HOST_INFECTIONMONKEY:
            hostname = f"monk{self.hosts[host_type.value].__len__()}"
            self.hosts[host_type.value].append(
                self.net.addDocker(
                    name=hostname,
                    ip=ip,
                    dimage='infectionmonkey',
                    dcmd='/etc/service/InfectionMonkey-v1.13.0.AppImage '
                    '--appimage-extract-and-run',
                    ports=[5000],
                    port_bindings={5000: 443},
                )
            )
        elif host_type == Host.HOST_COLLECTOR:
            hostname = f"coll{self.hosts[host_type.value].__len__()}"
            self.hosts[host_type.value].append(
                self.net.addDocker(
                    name=hostname,
                    ip=ip,
                    dimage='collector',
                    volumes=[f"{os.getcwd()}/traffic_dumps/:/mnt/vol:rw"]
                )
            )
        else:
            console.log(f"host type {host_type} does not exist",
                        style="red")

        console.log(f"added host [b]{hostname}[/b] with address {ip}")
        self.addLink(self.hosts[host_type.value][-1], self.switches[-1])

    def addSwitch(self):
        """
        Adds a generic Mininet switch to the running network. Switches have the
        naming convention of `sX` where `X` is the index of the switch.
        """
        i = self.switches.__len__()
        name = f"s{i}"
        self.switches.append(
            self.net.addSwitch(name)
        )

        console.log(f"added switch [b]{name}[/b]")

    def addLink(self, host_a, host_b):
        """
        Adds a generic Mininet link between `host_a` and `host_b`.
        """
        try:
            self.links.append(self.net.addLink(host_a, host_b))
            console.log(f"added link [b]{host_a} <-> {host_b}[/b]")
        except:
            console.log(f"failed to add link [b]{host_a} <-> {host_b}[/b]", 
                        style="red")

    def start(self):
        """
        Starts the Containernet instance.
        """
        try:
            self.net.start()
            console.log("🚀 BASSDN instance started")
        except:
            console.log("failed to start BASSDN instance!",
                        style="red")

    def commandLine(self):
        """
        Starts the Containernet command line tool.
        """
        try:
            CLI(self.net)
        except:
            console.log("containernet CLI raised an error",
                        style="red")
        finally:
            return

    def stop(self):
        """
        Stops the Containernet instance.
        """
        try:
            self.net.stop()
            console.log("stopped BASSDN instance")
        except:
            console.log("failed to stop BASSDN instance!",
                        style="red")


def get_host_ip():
    """
    Returns the IP Address of the host machine.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    s.connect(('254.254.254.254', 1))
    ip = s.getsockname()[0]
    s.close()
    return ip


def main(*, n_hosts: int = 4, v_hosts: int = 4, segments: int = 1,
         network_range: str = '10.0.0.0/24'):
    """
    Launches a software-defined network with vulnerable and non-vulnerable hosts
    as well as one Infection Monkey instance. 

    :param int n_hosts: Number of regular (non-vulnerable) hosts to deploy
    :param int v_hosts: Number of vulnerable hosts to deploy
    :param int segments: Number of network segments (i.e. switches) to deploy
    :param str network_range: CIDR IP range that the network will operate in
    """
    bassdn = BASSDN(network_range=network_range)

    total_hosts = n_hosts + v_hosts     # includes collector and monkey
    hosts_per_segment = total_hosts // segments

    # add hosts and link them by segment
    for _ in range(segments):
        bassdn.addSwitch()
        for _ in range(hosts_per_segment):
            if (n_hosts > 0):
                bassdn.addHost(Host.HOST_NORMAL)
                n_hosts = n_hosts - 1
            elif (v_hosts > 0):
                bassdn.addHost(Host.HOST_VULNERABLE)
                v_hosts = v_hosts - 1
    
    # add links to each switch
    for i, switch_a in enumerate(bassdn.switches):
        if i < (len(bassdn.switches) - 1):
            switch_b = bassdn.switches[i + 1]
            bassdn.addLink(switch_a, switch_b)

    """ always attaches to the last switch """
    # add infection monkey source
    bassdn.addHost(Host.HOST_INFECTIONMONKEY)
    # add a collector to dump traffic info
    bassdn.addHost(Host.HOST_COLLECTOR)
    # start collector
    bassdn.hosts[Host.HOST_COLLECTOR.value][0].cmd(
        f"tshark -i coll0-eth0 > /mnt/vol/coll0-traffic-" \
        f"{datetime.now().strftime('%d-%m-%Y-%H-%M-%S')}.dmp &"
    )
    console.log("started [b]data collector[/b] on [b]coll0[/b]\n" \
                f"[b]dump file[/b]: {os.getcwd()}/traffic_dumps/coll0-" \
                f"traffic-{datetime.now().strftime('%d-%m-%Y-%H-%M-%S')}.dmp")

    bassdn.start()

    console.print("\nPlease access the Infection Monkey webserver on "
                  f"https://{get_host_ip()}/",
                  style='bold',
                  justify='center')
    console.print("Upload the `monkey.conf` file to the configuration "
                  "settings to initialise the attack.\n",
                  justify='center')
    
    bassdn.commandLine()
    bassdn.stop()


if __name__ == "__main__":
    defopt.run(main, short={'n-hosts': 'n', 'v-hosts': 'v', 'segments': 's'})
