# simbpf
## Showcase:
Source code is quite compact and intuitive:
```
user@host:~/checkouts/simbpf/src$ cat ../examples/arp_or_udp.sb
u16@12: =0x0806 -> pass;
        =0x0800 -> u8@23: =17 -> pass.
 ```
 Generated eBPF code is quite efficient:
 ```
user@host:~/checkouts/simbpf/src$ ./simbpf -c ../examples/arp_or_udp.sb 
26/1024
0:      0x61, 8, 1, 0, 0
1:      0x61, 9, 1, 4, 0
2:      0xb7, 0, 0, 0, 1
3:      0xbf, 2, 8, 0, 0
4:      0x07, 2, 0, 0, 14
5:      0x2d, 2, 9, 19, 0
6:      0x69, 0, 8, 12, 0
7:      0xbf, 7, 0, 0, 0
8:      0xb7, 0, 0, 0, 2054
9:      0x1d, 7, 0, 13, 0
10:     0xb7, 0, 0, 0, 2048
11:     0x1d, 7, 0, 1, 0
12:     0x05, 0, 0, 12, 0
13:     0xbf, 2, 8, 0, 0
14:     0x07, 2, 0, 0, 24
15:     0x2d, 2, 9, 9, 0
16:     0x71, 0, 8, 23, 0
17:     0xbf, 7, 0, 0, 0
18:     0xb7, 0, 0, 0, 17
19:     0x1d, 7, 0, 1, 0
20:     0x05, 0, 0, 4, 0
21:     0xb7, 0, 0, 0, 2
22:     0x05, 0, 0, 2, 0
23:     0xb7, 0, 0, 0, 2
24:     0x05, 0, 0, 0, 0
25:     0x95, 0, 0, 0, 0
```
Compilation times are quite fast:
```
user@debra:~/checkouts/simbpf/src$ time ./simbpf -c ../examples/arp_or_udp.sb
26/1024
0:      0x61, 8, 1, 0, 0
.
.
.
25:     0x95, 0, 0, 0, 0

real    0m0.002s
user    0m0.002s
sys     0m0.001s
```
