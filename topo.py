
#!/usr/bin/env python
from mininet.topo import Topo

class BBTopo(Topo):
    "Simple topology for bufferbloat experiment."

    def __init__(self, n=2, **opts):
        Topo.__init__(self, **opts)
        # Here I have created a switch.  If you change its name, its
        # interface names will change from s0-eth1 to newname-eth1.
        hosts = []
        switch = self.addSwitch('s0')
        for h in xrange(n):
            hosts.append(self.addHost('h%s' % (h+1)))
        # Add links with appropriate characteristics
        # h1 <=> switch
        self.addLink(hosts[0], switch, bw=200, delay='1ms', max_queue_size=1000)
        self.addLink(hosts[1], switch, bw=50, delay='10ms', max_queue_size=500) # h2 <=> switch
        return

class TwoHostNInterfaceTopo(Topo):
    "Two hosts connected by N interfaces"

    def __init__(self, n, **opts):
        "n is the number of interfaces connecting the hosts."
        super(TwoHostNInterfaceTopo, self).__init__(**opts)

        # Note: switches are not strictly necessary, but they do give
        # visibility into traffic from the root namespace.
        SWITCHES = ['s%i' % i for i in range(1, n + 1)]
        for sw in SWITCHES:
            self.addSwitch(sw)

        HOSTS = ['h1', 'h2']
        for h in HOSTS:
            self.addHost(h)
            for sw in SWITCHES:
                self.addLink(h, sw)


class MMwaveTestTopo(Topo):
    "Topo1 Topology"

    def __init__(self, n=1, cpu=.2, mmwavebw=100, delay=None,
                 max_queue_size=1000, **params):

        # Initialize topo
        Topo.__init__(self, **params)
        # Host and link configuration
        hconfig = {'cpu': cpu}
        lconfig_eth = {'bw': 100, 'delay': '10ms', 'loss': 0,
                   'max_queue_size': max_queue_size, 'use_htb' : True }
        lconfig_mmwave = {'bw': 100, 'delay': '10ms', 'loss': 0,
                   'max_queue_size': 200,  'use_htb' : True  }
        lconfig_wifi = {'bw': 10, 'delay': '20ms', 'loss': 0,
                   'max_queue_size': 50,  'use_htb' : True  }

        # Switch ports 1:uplink 2:hostlink 3:downlink
        uplink, downlink = 1, 2

	    # Hosts and switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')


        sender = self.addHost('sender', **hconfig)
        receiver = self.addHost('receiver', **hconfig)


	    # Wire receiver
        self.addLink(receiver, s1, port1=0, port2=uplink, **lconfig_mmwave)
        self.addLink(receiver, s2, port1=1, port2=uplink, **lconfig_wifi)

        # Wire sender
    	self.addLink(sender, s1, port1=0, port2=downlink, **lconfig_eth)
    	self.addLink(sender, s2, port1=1, port2=downlink, **lconfig_eth)
