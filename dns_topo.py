#!/usr/bin/python
from mininet.net import Mininet
# Import NAT
from mininet.node import OVSController
from mininet.nodelib import NAT
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_topology():
    net = Mininet(controller=OVSController, link=TCLink)

    print("INFO: Adding controller")
    net.addController('c0')

    print("INFO: Adding hosts")
    # Add a defaultRoute for all hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
    h2 = net.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
    h3 = net.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254')
    h4 = net.addHost('h4', ip='10.0.0.4/24', defaultRoute='via 10.0.0.254')
    dns_resolver = net.addHost('dns', ip='10.0.0.5/24', defaultRoute='via 10.0.0.254')

    print("INFO: Adding NAT node for internet access")
    # Add the NAT node
    nat = net.addHost('nat', cls=NAT, ip='10.0.0.254/24', inNamespace=False)

    print("INFO: Adding switches")
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    print("INFO: Creating links")
    # Host links
    net.addLink(h1, s1, bw=100, delay='2ms')
    net.addLink(h2, s2, bw=100, delay='2ms')
    net.addLink(h3, s3, bw=100, delay='2ms')
    net.addLink(h4, s4, bw=100, delay='2ms')
    net.addLink(dns_resolver, s2, bw=100, delay='1ms')

    # Switch links
    net.addLink(s1, s2, bw=100, delay='5ms')
    net.addLink(s2, s3, bw=100, delay='8ms')
    net.addLink(s3, s4, bw=100, delay='10ms')

    # Link NAT to the central switch (s2)
    net.addLink(nat, s2)

    print("INFO: Starting network")
    net.start()

    print("INFO: Running CLI")
    CLI(net)

    print("INFO: Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()