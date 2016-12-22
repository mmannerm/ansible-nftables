#!/usr/bin/python -m pytest

from scapy.all import *

GW_ADDR = "192.168.1.102"
GW_ADDR_V6 = "fc00::102"
GW_INT = conf.route.route(GW_ADDR)[0]
GW_INT_V6 = conf.route6.route(GW_ADDR_V6)[0]

MY_ADDR = conf.route.route(GW_ADDR)[1]
MY_ADDR_V6 = conf.route6.route(GW_ADDR_V6)[1]


def test_ping_gw():
  p = sr1(IP(dst=GW_ADDR)/ICMP(), timeout=1)
  assert p[ICMP].type == ICMP.type.s2i["echo-reply"], "invalid response echo-reply != %r" % p[ICMP].type


def test_martian_destination():
  r = sr1(ARP(op=ARP.who_has, pdst=GW_ADDR), timeout=1)
  assert r[ARP].op == ARP.is_at, "unable to resolve gw mac address"
  p = srp1(Ether(src=r.hwdst, dst=r.hwsrc)/IP(src=MY_ADDR, dst=GW_ADDR)/ICMP(), timeout=1, iface=GW_INT)
  assert p, "gw is not responding to echo-request"
  p = srp1(Ether(src=r.hwdst, dst=r.hwsrc)/IP(src=MY_ADDR, dst='127.0.0.1')/ICMP(), timeout=1, iface=GW_INT)
  assert not p, "martian destination 127.0.0.1 accepted by gw"


def test_ping_gw_ipv6():
  p = sr1(IPv6(dst=GW_ADDR_V6)/ICMPv6EchoRequest(), timeout=1)
  assert p.type == ICMPv6EchoReply.type.s2i["Echo Reply"], "invalid response echo-reply != %r" % p.type


def test_martian_destination_ipv6():
  r = neighsol(GW_ADDR_V6, MY_ADDR_V6, GW_INT_V6)
  assert r and r.lladdr, "unable to resolve gw mac address"
  p = srp1(Ether(src=r.dst, dst=r.src)/IPv6(src=MY_ADDR_V6, dst=GW_ADDR_V6)/ICMPv6EchoRequest(), timeout=1, iface=GW_INT_V6)
  assert p, "gw is not responding to echo-request"
  p = srp1(Ether(src=r.dst, dst=r.src)/IPv6(src=MY_ADDR_V6, dst='::1')/ICMPv6EchoRequest(), timeout=1, iface=GW_INT_V6)
  assert not p, "martian destination ::1 accepted by gw"
