#!/usr/bin/python
"""
Test to validate MPTCP operation across at least two links.
"""

import sys
from subprocess import Popen, PIPE
from time import sleep
import termcolor as T
import argparse

from mininet.net import Mininet
from mininet.log import lg
from mininet.node import OVSKernelSwitch as Switch
from mininet.link import Link, TCLink
from mininet.util import makeNumeric, custom
from multiprocessing import Process
from util.monitor import monitor_devs_ng
import os
from topo import TwoHostNInterfaceTopo

# TODO: move to common location; code shared with DCTCP.
def progress(t):
    while t > 0:
        print T.colored('  %3d seconds  left\r' % (t), 'cyan'),
        t -= 1
        sys.stdout.flush()
        sleep(1)
    print '\r\n'

def sysctl_set(key, value):
    """Issue systcl for given param to given value and check for error."""
    p = Popen("sysctl -w %s=%s" % (key, value), shell=True, stdout=PIPE,
              stderr=PIPE)
    # Output should be empty; otherwise, we have an issue.
    stdout, stderr = p.communicate()
    stdout_expected = "%s = %s\n" % (key, value)
    if stdout != stdout_expected:
        raise Exception("Popen returned unexpected stdout: %s != %s" %
                        (stdout, stdout_expected))
    if stderr:
        raise Exception("Popen returned unexpected stderr: %s" % stderr)


def parse_args():
    parser = argparse.ArgumentParser(description="MPTCP 2-host n-switch test")
    parser.add_argument('--bw', '-B',
                        action="store",
                        help="Bandwidth of links",
                        required=True)

    parser.add_argument('-n',
                        action="store",
                        help="Number of switches.  Must be >= 2",
                        default=2)

    parser.add_argument('-t',
                        action="store",
                        help="Seconds to run the experiment",
                        default=2)

    parser.add_argument('--mptcp',
                        action="store_true",
                        help="Enable MPTCP (net.mptcp.mptcp_enabled)",
                        default=True)

    parser.add_argument('--pause',
                        action="store_true",
                        help="Pause before test start & end (to use wireshark)",
                        default=False)

    parser.add_argument('--ndiffports',
                        action="store",
                        help="Set # subflows (net.mptcp.mptcp_ndiffports)",
                        default=1)

    args = parser.parse_args()
    args.bw = float(args.bw)
    args.n = int(args.n)
    args.ndiffports = int(args.ndiffports)
    return args

def setup(args):
    """Enable MPTCP if true, disable if false"""
    if (args.mptcp):
        lg.info("Enable MPTCP\n")
        sysctl_set('net.mptcp.mptcp_enabled', 1)
        lg.info("setting MPTCP path manager to full mesh %s\n")
        sysctl_set('net.mptcp.mptcp_path_manager', 'fullmesh')

    #set_mptcp_ndiffports(args.ndiffports)


def run(args, net):
    seconds = int(args.t)
    h1 = net.getNodeByName('h1')
    h2 = net.getNodeByName('h2')
    h2.cmd('killall -9 iperf')
    for i in range(args.n):
	print "Configure %i interface at host........" % i
        # Setup IPs:
        h1.cmdPrint('ifconfig h1-eth%i 10.0.%i.3 netmask 255.255.255.0' % (i, i))
        h2.cmdPrint('ifconfig h2-eth%i 10.0.%i.4 netmask 255.255.255.0' % (i, i))

        if args.mptcp:
            lg.info("configuring source-specific routing tables for MPTCP\n")
            # This creates two different routing tables, that we use based on the
            # source-address.
            table = '%s' % (i + 1)
            #h1.cmdPrint('ip rule add from 10.0.%i.3 table %s' % (i, table))
            #h1.cmdPrint('ip route add 10.0.%i.0/24 dev h1-eth%s scope link table %s' % (i, i, table))
            h1.cmdPrint('ip route add default via 10.0.%i.1 dev h1-eth%s table %s' % (i, i, table))
            if not i:
                h1.cmdPrint('ip route add default scope global nexthop via 10.0.%i.1 dev h1-eth%s' % (i, i))
                h2.cmdPrint('ip route add default scope global nexthop via 10.0.%i.1 dev h2-eth%s' % (i, i))
            #h2.cmdPrint('ip rule add from 10.0.%i.4 table %s' % (i, table))
            #h2.cmdPrint('ip route add 10.0.%i.0/24 dev h2-eth%s scope link table %s' % (i, i, table))
            h2.cmdPrint('ip route add default via 10.0.%i.1 dev h2-eth%s table %s' % (i, i, table))

    # TODO: expand this to verify connectivity with a ping test.
    lg.info("pinging each destination interface\n")
    for i in range(args.n):
        h2_out = h2.cmd('ping -c 1 10.0.%i.3' % i)
        lg.info("ping test output: %s\n" % h2_out)
    for i in range(args.n):
        h1_out = h1.cmd('ping -c 1 10.0.%i.4' % i)
        lg.info("ping test output: %s\n" % h1_out)

    # TODO: start monitor mode
    #monitor = Process(target=monitor_devs_ng, args=('./test/bwm.txt', 1.0))
    #monitor.start()

    sleep(0.5) # Very important ! It takes sometime for the rule to be effective..
    for i in xrange(3):
        lg.info("iperfing %i\'s time" % (i+1))
        h2.cmd('iperf -s -i 1 &')

        cmd = 'iperf -c 10.0.0.4 -t %d -i 1' % seconds
        h1.sendCmd(cmd)
        progress(seconds + 1)
        h1_out = h1.waitOutput()
        lg.info("client output:\n%s\n" % h1_out)
        sleep(0.1)  # hack to wait for iperf server output.
        #out = h2.read(10000)
        #lg.info("server output: %s\n" % out)
        h2.cmd('killall -9 iperf')
        h1.cmd('killall -9 iperf')
        sleep(1)
        #monitor.terminate()
        #os.system("killall -9 bwm-ng")
    return None


def end(args):
    print "I am doing nothing"
    #set_mptcp_enabled(False)
    #set_mptcp_ndiffports(1)


def genericTest(args, topo, setup, run, end):
    link = custom(TCLink, bw=args.bw)
    net = Mininet(topo=topo, switch=Switch, link=link)
    setup(args)
    net.start()
    if args.pause:
        print "press enter to run test"
        raw_input()
    data = run(args, net)
    if args.pause:
        print "press enter to finish test"
        raw_input()
    net.stop()
    end(args)
    return data


def main():
    args = parse_args()
    lg.setLogLevel('info')
    topo = TwoHostNInterfaceTopo(n=args.n)
    genericTest(args, topo, setup, run, end)


if __name__ == '__main__':
    main()
