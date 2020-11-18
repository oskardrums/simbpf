#!/bin/sh
../src/simbpf -c ../examples/dangling_else.sb | diff expected/dangling_else.txt -
