#!/bin/sh
../src/simbpf -c ../examples/drop.sb | diff expected/drop.txt -
