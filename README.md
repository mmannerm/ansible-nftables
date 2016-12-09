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
