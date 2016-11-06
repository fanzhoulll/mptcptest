from helper import *
from collections import defaultdict
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--sport',
                    help="Enable the source port filter (0: not filter)",
                    action='store_true',
                    default=0)
parser.add_argument('--dport',
                    help="Enable the destination port filter (0: not filter)",
                    action='store_true',
                    default=5201)
parser.add_argument('-f',
                    dest="file",
                    nargs='+',
                    required=True)
parser.add_argument('-o',
                    '--out',
                    dest="out",
                    default=None)

'''
parser.add_argument('-H', '--histogram', dest="histogram",
                    help="Plot histogram of sum(cwnd_i)",
                    action="store_true",
                    default=False)
'''

args = parser.parse_args()

# Only works for single file, otherwise some changes should be made here
times = defaultdict(list)
cwnds = defaultdict(list)
rtts = defaultdict(list)

def first(lst):
    return map(lambda e: e[0], lst)

def second(lst):
    return map(lambda e: e[1], lst)

def getNumFields():
    linux_ver = os.uname()[2].split('.')[:2] # example '3.13.0-24-generic'
    ver_1, ver_2 = [int(ver_i) for ver_i in linux_ver]
    if (ver_1 == 3 and ver_2 >= 12) or (ver_1 > 3):
        num_fields = 11
    else:
        num_fields = 10
    return num_fields

"""
Sample line:
(pre-Linux 3.12):
2.221032535 10.0.0.2:39815 10.0.0.1:5001 32 0x1a2a710c 0x1a2a387c 11 2147483647 14592 85
(post-Linux 3.12):
0.004313854 192.168.56.101:22 192.168.56.1:57321 32 0xa34f92b0 0xa34f9240 10 2147483647 131024 1 43520

source code: http://lxr.free-electrons.com/source/net/ipv4/tcp_probe.c?v=3.12
0: Time in seconds
1: Source IP:Port
2: Dest IP: Port
3: Packet length (bytes)
4: snd_nxt
5: snd_una
6: snd_cwnd
7: ssthr
8: snd_wnd
9: srtt
10: rcv_wnd (3.12 and later)
"""
def parse_file(f):
    # Cannot just relys on port !
    num_fields = getNumFields()
    # defaultdict will init a value for non-existing key
    for l in open(f).xreadlines():
        fields = l.strip().split(' ')
        if len(fields) != num_fields:
            print "Unsupported tcpprobe results !"
            break
        saddr = fields[1]
        daddr = fields[2]
        try:
            sport = int(saddr.split(':')[1])
            dport = int(daddr.split(':')[1])
        except:
            #print "Cannot parse sport (%s), dport (%s), skip" % (fields[1], fields[2])
            continue
        if args.dport and dport != args.dport:
            continue
        if args.sport and sport != args.sport:
            continue
        time = float(fields[0])
        cwnd = int(fields[6])
        #print cwnd
        rtt = int(fields[-1]) if (num_fields == 10) else int(fields[-2])
        rtt_ms = rtt/1000
        times[saddr].append(time)
        cwnds[saddr].append(cwnd)
        rtts[saddr].append(rtt_ms)

def plot_cwnds():
    #events = []
    #added = defaultdict(int)

    m.rc('figure', figsize=(16, 6))
    fig = plt.figure()
    axPlot = fig.add_subplot(1, 1, 1)

    for saddr in sorted(cwnds.keys()):
        t = times[saddr]
        cwnd = cwnds[saddr]
        #events += zip(t, [sport]*len(t), cwnd)
        axPlot.plot(t, cwnd, label=saddr)

    axPlot.grid(True)
    axPlot.legend(loc='best')
    axPlot.set_xlabel("seconds")
    axPlot.set_ylabel("cwnd (pkt)")
    axPlot.set_title("TCP congestion window (cwnd) timeseries")

    if args.out:
        print 'saving to', args.out + '_cwnd.png'
        plt.savefig(args.out + '_cwnd.png')
    else:
        plt.show()

def plot_rtts():
    m.rc('figure', figsize=(16, 6))
    fig = plt.figure()
    axPlot = fig.add_subplot(1, 1, 1)

    for saddr in sorted(rtts.keys()):
        t = times[saddr]
        rtt = rtts[saddr]
        #events += zip(t, [sport]*len(t), cwnd)
        axPlot.plot(t, rtt, label=saddr)

    axPlot.grid(True)
    axPlot.legend(loc='best')
    axPlot.set_xlabel("seconds")
    axPlot.set_ylabel("RTT (ms)")
    axPlot.set_title("RTT timeseries")

    if args.out:
        print 'saving to', args.out + '_rtt.png'
        plt.savefig(args.out + '_rtt.png')
    else:
        plt.show()

'''
    events.sort()
    total_cwnd = 0
    cwnd_time = []

    min_total_cwnd = 10**10
    max_total_cwnd = 0
    totalcwnds = []
    for (t,p,c) in events:
        if added[p]:
            total_cwnd -= added[p]
        total_cwnd += c
        cwnd_time.append((t, total_cwnd))
        added[p] = c
        totalcwnds.append(total_cwnd)

    axPlot.plot(first(cwnd_time), second(cwnd_time), lw=2, label="$\sum_i W_i$")
    if args.histogram:
        axHist = fig.add_subplot(1, 2, 2)
        n, bins, patches = axHist.hist(totalcwnds, 50, normed=1, facecolor='green', alpha=0.75)

        axHist.set_xlabel("bins (KB)")
        axHist.set_ylabel("Fraction")
        axHist.set_title("Histogram of sum(cwnd_i)")
'''


def run():
    parse_file(args.file[0])
    plot_cwnds()
    plot_rtts()
    #plot_rtt(axPlot)

if __name__ == '__main__':
    run()
