Ansible Role: Nftables
======================

Installs and configures nftables on Ubuntu/Debian.

nftables replaces the popular {ip,ip6,arp,eb}tables. This software provides a new in-kernel packet classification framework that is based on a network-specific Virtual Machine (VM) and a new nft userspace command line tool. nftables reuses the existing Netfilter subsystems such as the existing hook infrastructure, the connection tracking system, NAT, userspace queueing and logging subsystem.

For more information about nftables, please see [nftables WIKI](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page) or [netfilter.org "nftables" project](https://www.netfilter.org/projects/nftables/).

Requirements
------------

- Linux kernel since 3.13, although newer kernel versions are recommended.


Role Variables
--------------

TODO

A description of the settable variables for this role should go here, including any variables that are in defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well.

Dependencies
------------

None.

Example Playbook
----------------

TODO

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: all
      roles:
         - { role: mmannerm.nftables }

References
----------

## Security and Protocols

- [IETF Draft: Operational Security Considerations for IPv6 Networks](https://tools.ietf.org/html/draft-ietf-opsec-v6-10), March 2017
- [IETF Draft: Recommendations on Filtering IPv6 Packets Containing IPv6 Extension Headers](https://tools.ietf.org/html/draft-ietf-opsec-ipv6-eh-filtering-02), October 2016
- [Firewall Best Practices](https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2016-09-1/NET-2016-09-1_01.pdf), September 2016
- [IETF Draft: Defeating attacks which employ Forged ICMP/ICMPv6 Error Messages (expired)](https://tools.ietf.org/html/draft-gont-opsec-icmp-ingress-filtering-02), March 2016
- [RFC 7126: Recommendations on Filtering of IPv4 Packets Containing IPv4 Options](https://tools.ietf.org/html/rfc7126), February 2014
- [IETF Draft: Recommendations for filtering ICMP messages (expired)](https://tools.ietf.org/html/draft-ietf-opsec-icmp-filtering-04), July 2013
- [RFC 6918: Formally Deprecating Some ICMPv4 Message Types](https://tools.ietf.org/html/rfc6918), April 2013
- [RFC 6633: Deprecation of ICMP Source Quench Messages](https://tools.ietf.org/html/rfc6633), May 2012
- [RFC 6092: Recommended Simple Security Capabilities in Customer Premises Equipment (CPE) for Providing Residential IPv6 Internet Service](https://tools.ietf.org/html/rfc6092), January 2011
- [RFC 5927: ICMP attacks against TCP](https://tools.ietf.org/html/rfc5927), July 2010
- [RFC 4890: Recommendations for Filtering ICMPv6 Messages in Firewalls](https://tools.ietf.org/html/rfc4890), May 2007

- [RFC 4443: Internet Control Message Protocol (ICMPv6)](https://tools.ietf.org/html/rfc4443), March 2006
-- Section 2.4 Message Processing Rules

## Tools

- [Network packet forgery with Scapy](http://www.secdev.org/conf/scapy_pacsec05.handout.pdf)

License
-------

Copyright 2016 Mika Mannermaa

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author Information
------------------

- [Mika Mannermaa](https://github.com/mmannerm)
