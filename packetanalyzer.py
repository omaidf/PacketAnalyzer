import dpkt
import colorama
from colorama import Fore, Back, Style
import socket
from geoip import geolite2
import sys


if len(sys.argv) !=2:
    print('Usage: python packetanalyzer.log capture.pcap')
    sys.exit(0)

file = sys.argv[1]
f = open(file)
hosts = []
methods = []
useragents = []
ignoredextensions = ['jpg','css','gif','png']
ips = []
countries = []

def analyze(payload,ip):
    if any(i in payload.uri for i in ignoredextensions):
        pass
    else:
        print payload.method, payload.uri
        print payload.headers['host'],"\n"
    match = geolite2.lookup(ip)
    countries.append(match.country)
    useragents.append(payload.headers['user-agent'])
    hosts.append(payload.headers['host'])
    methods.append(payload.method)
    ips.append(ip)

def start():
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if tcp.dport == 80 and len(tcp.data) > 0:
            payload = dpkt.http.Request(tcp.data)
            ipdest = inet_to_str(ip.dst)
            analyze(payload,ipdest)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def counter(list):
    dic = dict((x,list.count(x)) for x in set(list))
    for key, value in sorted(dic.iteritems(), key=lambda (k,v): (v,k)):
        print "%s: %s" % (key, value)

def showstats():
    #print statistics of the capture pcap
    print Fore.RED + "Top Hosts:"
    counter(hosts)
    print Fore.GREEN + "Top Methods:"
    counter(methods)
    print Fore.YELLOW + "Top User Agents:"
    counter(useragents)
    print Fore.RED + "IP Addresses:"
    counter(ips)
    print Fore.GREEN + "Countries:"
    counter(countries)
    f.close()
    print (Style.RESET_ALL)

start()
showstats()