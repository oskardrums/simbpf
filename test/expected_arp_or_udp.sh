#!/bin/sh
../src/simbpf -c ../examples/arp_or_udp.sb | diff expected/arp_or_udp.txt -
