#!/bin/sh
valgrind --leak-check=full --error-exitcode=1 ../src/simbpf < ../examples/arp_or_udp.sb
