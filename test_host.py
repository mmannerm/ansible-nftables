#!/usr/bin/python -m pytest

from scapy.all import *

RUNNER_ADDR = "192.168.1.101"
RUNNER_ADDR_V6 = "fc00::101"

GW_ADDR = "192.168.1.102"
GW_ADDR_PRIVATE = "192.168.2.102"
GW_ADDR_V6 = "fc00::102"
GW_ADDR_V6_PRIVATE = "fc00::1:102"
GW_INT_PRIVATE = conf.route.route(GW_ADDR_PRIVATE)[0]
GW_INT_V6_PRIVATE = conf.route6.route(GW_ADDR_V6_PRIVATE)[0]

MY_ADDR = conf.route.route(GW_ADDR_PRIVATE)[1]
MY_ADDR_V6 = conf.route6.route(GW_ADDR_V6_PRIVATE)[1]


def test_ping_gw():
  p = sr1(IP(dst=GW_ADDR_PRIVATE)/ICMP(), timeout=1)
  assert p[ICMP].type == ICMP.type.s2i["echo-reply"], "invalid response echo-reply != %r" % p[ICMP].type
  p = sr1(IP(dst=GW_ADDR)/ICMP(), timeout=1)
  assert p[ICMP].type == ICMP.type.s2i["echo-reply"], "invalid response echo-reply != %r" % p[ICMP].type


def test_martian_destination():
  r = sr1(ARP(op=ARP.who_has, pdst=GW_ADDR_PRIVATE), timeout=1)
  assert r[ARP].op == ARP.is_at, "unable to resolve gw mac address"
  p = srp1(Ether(src=r.hwdst, dst=r.hwsrc)/IP(src=MY_ADDR, dst=GW_ADDR_PRIVATE)/ICMP(), timeout=1, iface=GW_INT_PRIVATE)
  assert p, "gw is not responding to echo-request"
  p = srp1(Ether(src=r.hwdst, dst=r.hwsrc)/IP(src=MY_ADDR, dst='127.0.0.1')/ICMP(), timeout=1, iface=GW_INT_PRIVATE)
  assert not p, "martian destination 127.0.0.1 accepted by gw"


def test_ping_gw_ipv6():
  p = sr1(IPv6(dst=GW_ADDR_V6_PRIVATE)/ICMPv6EchoRequest(), timeout=1)
  assert p.type == ICMPv6EchoReply.type.s2i["Echo Reply"], "invalid response echo-reply != %r" % p.type
  p = sr1(IPv6(dst=GW_ADDR_V6)/ICMPv6EchoRequest(), timeout=1)
  assert p.type == ICMPv6EchoReply.type.s2i["Echo Reply"], "invalid response echo-reply != %r" % p.type


def test_martian_destination_ipv6():
  r = neighsol(GW_ADDR_V6_PRIVATE, MY_ADDR_V6, GW_INT_V6_PRIVATE)
  assert r and r.lladdr, "unable to resolve gw mac address"
  p = srp1(Ether(src=r.dst, dst=r.src)/IPv6(src=MY_ADDR_V6, dst=GW_ADDR_V6_PRIVATE)/ICMPv6EchoRequest(), timeout=1, iface=GW_INT_V6_PRIVATE)
  assert p, "gw is not responding to echo-request"
  p = srp1(Ether(src=r.dst, dst=r.src)/IPv6(src=MY_ADDR_V6, dst='::1')/ICMPv6EchoRequest(), timeout=1, iface=GW_INT_V6_PRIVATE)
  assert not p, "martian destination ::1 accepted by gw"


def test_ct_invalid_ssh():
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = sr1(IP(dst=GW_ADDR_PRIVATE)/TCP(dport=22, flags="FPU"), timeout=1, iface=GW_INT_PRIVATE)
  assert not p, "Invalid connection state to ssh to gw not dropped by gw"
  p = sr1(IP(dst=GW_ADDR_PRIVATE)/TCP(dport=22, flags="S"), timeout=1, iface=GW_INT_PRIVATE)
  assert p, "new connection state to ssh to gw not accepted by gw"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = sr1(IP(dst=GW_ADDR_PRIVATE)/TCP(dport=23, flags="FPU"), timeout=1, iface=GW_INT_PRIVATE)
  assert not p, "Invalid connection state to telnet to gw not dropped by gw"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = sr1(IP(dst=RUNNER_ADDR)/TCP(dport=22, flags="FPU"), timeout=1, iface=GW_INT_PRIVATE)
  assert not p, "Invalid connection state to ssh to host not dropped by gw"
  p = sr1(IP(dst=RUNNER_ADDR)/TCP(dport=22, flags="S"), timeout=1, iface=GW_INT_PRIVATE)
  assert p, "new connection state to ssh to host not accepted by gw"


def test_ct_invalid_ssh_ipv6():
  r = neighsol(GW_ADDR_V6_PRIVATE, MY_ADDR_V6, GW_INT_V6_PRIVATE)
  assert r and r.lladdr, "unable to resolve gw mac address"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = srp1(Ether(dst=r.src)/IPv6(dst=GW_ADDR_V6_PRIVATE)/TCP(dport=22, flags="FPU"), timeout=1, iface=GW_INT_V6_PRIVATE)
  assert not p, "Invalid connection state to ssh not dropped by gw"
  p = srp1(Ether(dst=r.src)/IPv6(dst=GW_ADDR_V6_PRIVATE)/TCP(dport=22, flags="S"), timeout=1, iface=GW_INT_V6_PRIVATE)
  assert p, "new connection state to ssh not accepted by gw"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = srp1(Ether(dst=r.src)/IPv6(dst=GW_ADDR_V6_PRIVATE)/TCP(dport=23, flags="FPU"), timeout=1, iface=GW_INT_V6_PRIVATE)
  assert not p, "Invalid connection state to telnet not dropped by gw"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = srp1(Ether(dst=r.src)/IPv6(dst=RUNNER_ADDR_V6)/TCP(dport=22, flags="FPU"), timeout=1, iface=GW_INT_V6_PRIVATE)
  assert not p, "Invalid connection state to ssh to runner not dropped by gw"
  p = srp1(Ether(dst=r.src)/IPv6(dst=RUNNER_ADDR_V6)/TCP(dport=22, flags="S"), timeout=1, iface=GW_INT_V6_PRIVATE)
  assert p, "new connection state to ssh to runner not accepted by gw"
