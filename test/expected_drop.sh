#!/bin/sh
../src/simbpf -i ../examples/drop.sb | diff expected/drop.txt -
