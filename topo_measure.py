#!/usr/bin/python

"CS 244 Assignment 3: MPTCP over wireless links"

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, output
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange, custom, quietRun, dumpNetConnections
from mininet.cli import CLI

from time import sleep, time
from multiprocessing import Process
from subprocess import Popen, PIPE
import termcolor as T
import argparse

import sys
import os
from util.monitor import monitor_devs_ng

from topo import *

def cprint(s, color, cr=True):
    """Print in color
       s: string to print
       color: color to use"""
    if cr:
        print T.colored(s, color)
    else:
        print T.colored(s, color),


def parse_args():
    parser = argparse.ArgumentParser(description="Parking lot tests")
    parser.add_argument('--bw', '-b',
                        type=float,
                        help="Bandwidth of network links",
                        required=True)

    parser.add_argument('--mptcp',
                        type=bool,
                        help="Enable MPTCP or not",
                        default=False)

    parser.add_argument('--backup',
                        type=bool,
                        help="Enable MPTCP backup mode or not",
                        default=False)

    parser.add_argument('--tcpdump',
                        type=bool,
                        help="Enable tcpdump or not",
                        default=False)

    parser.add_argument('--dir', '-d',
                        help="Directory to store outputs",
                        default="results")

    #parser.add_argument('-n',
    #                    type=int,
    #                    help=("Number of senders in the topo."
    #                    "Must be >= 1"),
    #                    required=False)

    #parser.add_argument('--cli', '-c',
    #                    action='store_true',
    #                    help='Run CLI for topology debugging purposes')

    parser.add_argument('-cc',
                        type=str,
                        help="Congestion Control Protocol.",
                        default="reno")

    parser.add_argument('--time', '-t',
                        dest="time",
                        type=int,
                        help="Duration of the experiment.",
                        default=10)

    parser.add_argument('--buffer', '-s',
                        dest="size",
                        type=int,
                        help="Size of buffer.")
    return parser.parse_args()

def progress(t):
       # Begin: Template code
    while t > 0:
        cprint('  %3d seconds left  \r' % (t), 'cyan', cr=False)
        t -= 1
        sys.stdout.flush()
        sleep(1)

def start_tcpprobe(args):
    os.system("rmmod tcp_probe 1>/dev/null 2>&1; modprobe tcp_probe full=1;")
    Popen("cat /proc/net/tcpprobe > %s/tcpprobe.txt" % (args.dir),
          shell=True)

def start_tcpdump(net, args):
    # Just in case
    sender = net.getNodeByName('sender')
    sender.cmd("pkill tcpdump")
    sender.cmd("tcpdump -n tcp -i sender-eth0 -p -s 96 -w %s/packettrace.pcap &" % (args.dir))


def configIP(net, args):
    # Setup receiver IP configuration
    recvr = net.getNodeByName('receiver')
    sender = net.getNodeByName('sender')
    for i in xrange(1):
        lg.info("*** Config for the %s\'s interface.......\n" % i)
        #sender.cmdPrint('ifconfig sender-eth%i 10.0.%i.3 netmask 255.255.255.0' % (i, i))
        sender.setIP('10.0.%s.3' % i, 24, 'sender-eth%i' % i)
        recvr.setIP('10.0.%s.4' % i, 24, 'receiver-eth%i' % i)
        #dev = 'sender-eth%i' % i
        #table = "%s" % (i+1)
        #sender.cmd('ip rule add from 10.0.%i.3 table %s' % (i, table))
        #sender.cmd('ip route add 10.0.%i.0/24 dev %s scope link table %s' % (i, dev, table))
        #sender.cmd('ip route add default via 10.0.%i.1 dev %s table %s' % (i, dev, table))
    lg.info(recvr.cmd('ip route'))
    lg.info(sender.cmd('ip route'))
    if args.backup:
        # Enable backup mode
        recvr.cmd("ip link set dev receiver-eth1 multipath backup")


def configBuf(net, args):
    recvr = net.getNodeByName('receiver')
    sender = net.getNodeByName('sender')
    lg.info("Sender/Receiver buffer setting")
    print sender.cmd("sysctl net.ipv4.tcp_rmem")
    print sender.cmd("sysctl net.ipv4.tcp_wmem")
    print recvr.cmd("sysctl net.ipv4.tcp_rmem")
    print recvr.cmd("sysctl net.ipv4.tcp_wmem")

'''

def configBuf(net, args):
    recvr = net.getNodeByName('receiver')
    sender = net.getNodeByName('sender')
    sender.cmd("echo 'net.ipv4.tcp_rmem=%s %s %s'>> /etc/sysctl.conf" % (args.size, args.size, args.size))
    sender.cmd(("echo 'net.ipv4.tcp_wmax=%s' >> /etc/sysctl.conf" % args.size))
    sender.cmd(("echo 'net.ipv4.tcp_rmax=%s' >> /etc/sysctl.conf" % args.size))
    sender.cmd('sysctl -p')
    recvr.cmd("echo 'net.ipv4.tcp_rmem=%s %s %s'>> /etc/sysctl.conf" % (args.size, args.size, args.size))
    recvr.cmd(("echo 'net.ipv4.tcp_wmax=%s' >> /etc/sysctl.conf" % args.size))
    recvr.cmd(("echo 'net.ipv4.tcp_rmax=%s' >> /etc/sysctl.conf" % args.size))
    recvr.cmd("echo 'net.ipv4.tcp_rmax=51200' >> /etc/sysctl.conf")
    recvr.cmd('sysctl -p')
    '''

def finish(recvr, monitor):
    lg.info("Killing iperf\n")
    recvr.cmd('pkill iperf')
    monitor.terminate()
    lg.info("Killing tcpprobe\n")
    os.system("killall -9 cat; rmmod tcp_probe")
    lg.info("Killing bwm-ng\n")
    os.system("killall -9 bwm-ng")

def sysctl_set(key, value):
    """Issue systcl for given param to given value and check for error."""
    p = Popen("sysctl -w %s=%s" % (key, value), shell=True, stdout=PIPE,
              stderr=PIPE)
    stdout, stderr = p.communicate()
    stdout_expected = "%s = %s\n" % (key, value)
    if stdout != stdout_expected:
        raise Exception("Popen returned unexpected stdout: %s != %s" %
                        (stdout, stdout_expected))
    if stderr:
        raise Exception("Popen returned unexpected stderr: %s" % stderr)

def configMPTCP(net, args):
    # Config IP, routing table
    configIP(net, args)
    if (args.mptcp):
        # Enable MPTCP
        sysctl_set('net.mptcp.mptcp_enabled', 1)
        # Set path manager
        sysctl_set('net.mptcp.mptcp_path_manager', 'fullmesh')
        #os.system('cat /sys/module/mptcp_fullmesh/parameters/num_subflows')
        # sysctl_set('net.mptcp.mptcp_scheduler', 'redundant')
        # Config Congestion Control
        # sysctl_set('net.ipv4.tcp_congestion_control', 'lia')
    else:
        try:
            # Try to disable MPTCP, if fail, it means MPTCP is not installed
            sysctl_set('net.mptcp.mptcp_enabled', 0)
        except:
            lg.info("May be mptcp is not installed ?\n")
        sysctl_set('net.ipv4.tcp_congestion_control', args.cc)

def runIperf(net, args):
    recvr = net.getNodeByName('receiver')
    sender = net.getNodeByName('sender')
    recvr.cmd('iperf3 -s > %s/receiver.txt &' % args.dir)
    # Wait iperf3 server get start
    sleep(0.1)
    sender.sendCmd('iperf3 -c 10.0.0.4 -t %d -i 1' % (args.time))
    s1 = net.getNodeByName('s1')
    s2 = net.getNodeByName('s2')
    for i in xrange(0):
        # Turn off and turn on links
        sleep(5)
        #recvr.cmd('ifconfig receiver-eth0 down')
        #s1.cmd('tc qdisc change dev s1-eth1 parent 5:1 netem rate 10Mbit')
        s1.cmd('ifconfig s1-eth1 down')
        sleep(5)
        s1.cmd('ifconfig s1-eth1 up')
    #sleep(5)
    #s1.cmd('tc qdisc change dev s1-eth1 parent 5:1 netem rate 5Mbit')
    #sleep(5)
    #s1.cmd('tc qdisc change dev s1-eth1 parent 5:1 netem rate 150Mbit')
    # Wait for outputs and finish
    progress(args.time)

    snd_out = sender.waitOutput()
    lg.info("Sender output:\n%s\n" % snd_out)
    with open("%s/sender.txt" % args.dir, "w") as f:
        f.write(snd_out)
    sleep(0.1)  # hack to wait for iperf sender output.
    lg.info("Killing iperf\n")
    recvr.cmd('pkill iperf')

def runWget(net, args):
    recvr = net.getNodeByName('receiver')
    sender = net.getNodeByName('sender')
    s1 = net.getNodeByName('s1')
    s2 = net.getNodeByName('s2')
    # sender: 10.0.0.3
    # receiver: 10.0.0.4
    sender.cmd('python -m SimpleHTTPServer 80 >& %s/httpserver.log &' % args.dir)
    # Wait for sender to execute the server
    sleep(0.1)
    recvr.sendCmd('wget -O %s/wgetedfile - http://10.0.0.3:80/testsmall' % args.dir)
    # Turn off and turn on links
    sleep(5)
    #s1.cmd('tc qdisc change dev s1-eth1 parent 5:1 netem rate 15Mbit')
    #sleep(0.5)
    #s2.cmd('ifconfig s1-eth1 up')
    #s2.cmd('tc qdisc change dev s1-eth1 parent 5:1 netem rate 150Mbit')
    # Wait for outputs and finish
    #progress(seconds)

    recvr_out = recvr.waitOutput()
    lg.info("Wget output:\n%s\n" % recvr_out)
    #sender.cmd('pkill python')

def run(net, args):
    "Run experiment"
    # seconds = args.time
    # Prepare, start monitor, tcp_probe, etc
    monitor = Process(target=monitor_devs_ng,
            args=('%s/bwm.txt' % args.dir, 0.1))
    monitor.start()
    start_tcpprobe(args)
    if args.tcpdump:
        start_tcpdump(net, args)
    # Get receiver and clients
    # recvr = net.getNodeByName('receiver')
    # sender = net.getNodeByName('sender')
    # s1 = net.getNodeByName('s1')
    # s2 = net.getNodeByName('s2')
    # Change buffer sizes
    #configBuf(net, args)
    # Start real experiments
    sleep(1) # !!! Important, otherwise MPTCP won't start
    runIperf(net, args)
    #runWget(net, args)

    # Finish experiment
    monitor.terminate()
    lg.info("Killing tcpprobe\n")
    os.system("killall -9 cat; rmmod tcp_probe")
    lg.info("Killing bwm-ng\n")
    os.system("killall -9 bwm-ng")
    if args.tcpdump:
        lg.info("Killing tcpdump\n")
        os.system("killall -9 tcpdump")

def check_prereqs():
    "Check for necessary programs"
    prereqs = ['telnet', 'bwm-ng', 'iperf', 'ping']
    for p in prereqs:
        if not quietRun('which ' + p):
            raise Exception((
                'Could not find %s - make sure that it is '
                'installed and in your $PATH') % p)

def main():
    "Parse argument"
    args = parse_args()

    if not os.path.exists(args.dir):
        os.makedirs(args.dir)

    "Create network topology, running experiments"
    lg.setLogLevel('info')
    start = time()
    cprint("*** Creating network topology:", "yellow")
    topo = MMwaveTestTopo(mmwavebw=args.bw)
    host = custom(CPULimitedHost, cpu=0.2)  # 20% of system bandwidth (why?)
    link = custom(TCLink)
    net = Mininet(topo=topo, host=host, link=link)
    net.start()
    cprint("*** Dumping network connections:", "green")
    dumpNetConnections(net)
    cprint("*** Configure MPTCP", "red")
    configMPTCP(net, args)
    cprint("*** Testing connectivity", "blue")
    net.pingAll()
    cprint("*** Running experiment", "magenta")
    #CLI(net)
    run(net, args)
    end = time()
    cprint("*** Finishing experiment, took %.3f seconds" % (end - start), "yellow")
    net.stop()


if __name__ == '__main__':
    check_prereqs()
    main()
