#!/usr/bin/python -m pytest

from scapy.all import *

GW_ADDR = "192.168.1.102"
GW_ADDR_PRIVATE = "192.168.2.102"
GW_ADDR_V6 = "fc00::102"
GW_INT = conf.route.route(GW_ADDR)[0]
GW_INT_V6 = conf.route6.route(GW_ADDR_V6)[0]

HOST_ADDR = "192.168.3.103"
HOST_ADDR_PRIVATE = "192.168.2.103"
HOST_INT = conf.route.route(HOST_ADDR)[0]

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


def test_routing():
  p = sr1(IP(dst=HOST_ADDR_PRIVATE)/ICMP(), timeout=1, iface=GW_INT)
  assert p[ICMP].type == ICMP.type.s2i["echo-reply"], "invalid response to echo-reply != %r" % p[ICMP].type
  p = sr1(IP(dst=GW_ADDR_PRIVATE)/ICMP(), timeout=1, iface=HOST_INT)
  assert not p, "host is forwarding"


def test_martian_destination_ipv6():
  r = neighsol(GW_ADDR_V6, MY_ADDR_V6, GW_INT_V6)
  assert r and r.lladdr, "unable to resolve gw mac address"
  p = srp1(Ether(src=r.dst, dst=r.src)/IPv6(src=MY_ADDR_V6, dst=GW_ADDR_V6)/ICMPv6EchoRequest(), timeout=1, iface=GW_INT_V6)
  assert p, "gw is not responding to echo-request"
  p = srp1(Ether(src=r.dst, dst=r.src)/IPv6(src=MY_ADDR_V6, dst='::1')/ICMPv6EchoRequest(), timeout=1, iface=GW_INT_V6)
  assert not p, "martian destination ::1 accepted by gw"


def test_ct_invalid_ssh():
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = sr1(IP(dst=GW_ADDR)/TCP(dport=22, flags="FPU"), timeout=1, iface=GW_INT)
  assert not p, "Invalid connection state to ssh to gw not dropped by gw"
  p = sr1(IP(dst=GW_ADDR)/TCP(dport=22, flags="S"), timeout=1, iface=GW_INT)
  assert p, "new connection state to ssh to gw not accepted by gw"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = sr1(IP(dst=GW_ADDR)/TCP(dport=23, flags="FPU"), timeout=1, iface=GW_INT)
  assert not p, "Invalid connection state to telnet to gw not dropped by gw"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = sr1(IP(dst=HOST_ADDR_PRIVATE)/TCP(dport=22, flags="FPU"), timeout=1, iface=GW_INT)
  assert not p, "Invalid connection state to ssh to host not dropped by gw"
  p = sr1(IP(dst=HOST_ADDR_PRIVATE)/TCP(dport=22, flags="S"), timeout=1, iface=GW_INT)
  assert p, "new connection state to ssh to host not accepted by gw"


def test_ct_invalid_ssh_ipv6():
  r = neighsol(GW_ADDR_V6, MY_ADDR_V6, GW_INT_V6)
  assert r and r.lladdr, "unable to resolve gw mac address"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = srp1(Ether(dst=r.src)/IPv6(dst=GW_ADDR_V6)/TCP(dport=22, flags="FPU"), timeout=1, iface=GW_INT_V6)
  assert not p, "Invalid connection state to ssh not dropped by gw"
  p = srp1(Ether(dst=r.src)/IPv6(dst=GW_ADDR_V6)/TCP(dport=22, flags="S"), timeout=1, iface=GW_INT_V6)
  assert p, "new connection state to ssh not accepted by gw"
  # Test with Xmas scan, no reply (RST or anything) should be sent
  p = srp1(Ether(dst=r.src)/IPv6(dst=GW_ADDR_V6)/TCP(dport=23, flags="FPU"), timeout=1, iface=GW_INT_V6)
  assert not p, "Invalid connection state to telnet not dropped by gw"


def test_deprecated_icmp():
  p = sr1(IP(dst=GW_ADDR)/ICMP(type="timestamp-request"), timeout=1, iface=GW_INT)
  assert not p, "timestamp-request accepted by gw"
  p = sr1(IP(dst=HOST_ADDR_PRIVATE)/ICMP(type="timestamp-request"), timeout=1, iface=GW_INT)
  assert not p, "timestamp-request routed by gw"
  # address-mask-request should already be handled by the kernel
  p = sr1(IP(dst=GW_ADDR)/ICMP(type="address-mask-request"), timeout=1, iface=GW_INT)
  assert not p, "address-mask-request accepted by gw"
  p = sr1(IP(dst=HOST_ADDR_PRIVATE)/ICMP(type="address-mask-request"), timeout=1, iface=GW_INT)
  assert not p, "address-mask-request routed by gw"
  # information-request should already be handled by the kernel
  p = sr1(IP(dst=GW_ADDR)/ICMP(type="information-request"), timeout=1, iface=GW_INT)
  assert not p, "information-request accepted by gw"
  p = sr1(IP(dst=HOST_ADDR_PRIVATE)/ICMP(type="information-request"), timeout=1, iface=GW_INT)
  assert not p, "information-request routed by gw"


def test_source_quench():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((GW_ADDR, 22))
  data = str(IP(dst=GW_ADDR)/TCP(dport=s.getpeername()[1], sport=s.getsockname()[1]))
  # TODO: source quench does not send reply, so have to check with tcpdump and dmesg
  send(IP(dst=GW_ADDR)/ICMP(type="source-quench")/data, iface=GW_INT)
  s.close()


# TODO
def test_ping_of_death():
  p = sr1(fragment(IP(dst=GW_ADDR)/ICMP()/("X"*60000)), timeout=1, iface=GW_INT)
  assert p[ICMP].type == ICMP.type.s2i["dest-unreach"], "expected dest-unreach, received: %r" % p[ICMP].type
  assert p[ICMP].code == 2, "expected protocol-unreachable, received: %r " % p[ICMP].code


# TODO
def test_nestea_attack():
  send(IP(dst=GW_ADDR, id=42, flags="MF")/UDP()/("X"*10), iface=GW_INT)
  send(IP(dst=GW_ADDR, id=42, frag=48)/("X"*116), iface=GW_INT)
  send(IP(dst=GW_ADDR, id=42, flags="MF")/UDP()/("X"*224), iface=GW_INT)
