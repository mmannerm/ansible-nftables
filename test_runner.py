#!/usr/bin/python -m pytest

from scapy.all import *

GW_ADDR = "192.168.1.102"
GW_INT = conf.route.route(GW_ADDR)[0]


def test_ping_gw():
  p = sr1(IP(dst=GW_ADDR)/ICMP(), timeout=1)
  assert p[ICMP].type == ICMP.type.s2i["echo-reply"], "invalid response echo-reply != %r" % p[ICMP].type


def test_martian_destination():
  r = sr1(ARP(op=ARP.who_has, pdst=GW_ADDR), timeout=1)
  assert r[ARP].op == ARP.is_at, "unable to resolve gw mac address"
  p = srp1(Ether(src=r.hwdst, dst=r.hwsrc)/IP(dst=GW_ADDR)/ICMP(), timeout=1, iface=GW_INT)
  assert p, "gw is not responding to echo-request"
  p = srp1(Ether(src=r.hwdst, dst=r.hwsrc)/IP(dst='127.0.0.1')/ICMP(), timeout=1, iface=GW_INT)
  assert not p, "martian destination 127.0.0.1 accepted by gw"
