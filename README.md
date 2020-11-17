# simbpf
## Showcase:
Source code is quite compact and intuitive:
```
user@host:~/simbpf/src$ cat ../examples/arp_or_udp.sb
u16@12: =0x0806 -> pass;
        =0x0800 -> u8@23: =17 -> pass.
 ```
 Generated eBPF code is quite efficient:
 ```
user@host:~/simbpf/src$ ./simbpf -c ../examples/arp_or_udp.sb 
30/64
0:	0x61, 8, 1, 0, 0
1:	0x61, 9, 1, 4, 0
2:	0xb7, 0, 0, 0, 1
3:	0xbf, 2, 8, 0, 0
4:	0x07, 2, 0, 0, 14
5:	0x2d, 2, 9, 23, 0
6:	0x69, 0, 8, 12, 0
7:	0xbf, 7, 0, 0, 0
8:	0xb7, 0, 0, 0, 2054
9:	0x1d, 7, 0, 4, 0
10:	0xb7, 0, 0, 0, 2048
11:	0x1d, 7, 0, 4, 0
12:	0xb7, 0, 0, 0, 1
13:	0x05, 0, 0, 15, 0
14:	0xb7, 0, 0, 0, 2
15:	0x05, 0, 0, 13, 0
16:	0xbf, 2, 8, 0, 0
17:	0x07, 2, 0, 0, 24
18:	0x2d, 2, 9, 10, 0
19:	0x05, 0, 0, 9, 0
20:	0x71, 0, 8, 23, 0
21:	0xbf, 7, 0, 0, 0
22:	0xb7, 0, 0, 0, 17
23:	0x1d, 7, 0, 2, 0
24:	0xb7, 0, 0, 0, 1
25:	0x05, 0, 0, 3, 0
26:	0xb7, 0, 0, 0, 2
27:	0x05, 0, 0, 1, 0
28:	0x05, 0, 0, 0, 0
29:	0x95, 0, 0, 0, 0
```
Compilation times are quite fast:
```
user@host:~/simbpf/src$ time ./simbpf -c ../examples/arp_or_udp.sb
30/64
0:      0x61, 8, 1, 0, 0
.
.
.
29:     0x95, 0, 0, 0, 0

real    0m0.004s
user    0m0.003s
sys     0m0.001s
```
