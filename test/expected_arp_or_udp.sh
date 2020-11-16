#!/bin/sh
../src/simbpf -i ../examples/arp_or_udp.sb | diff expected/arp_or_udp.txt -
