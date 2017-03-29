# Development


# Molecule Test Setup

```
 ,------------.
 |runner (101)|------.
 `------------'      |
   |                 |
   | "public net"    |
   | 192.168.1.xxx   |
   | fc00::xxx       |
   |                 |
 ,------------.      | "backchannel"
 |  gw (102)  |      | 192.168.3.xxx
 `------------'      |
   |                 |
   | "private net"   |
   | 192.168.2.xxx   |
   | fc00::1:xxx     |
   |                 |
 ,------------.      |
 | host (103) |------'
 `------------'
```

