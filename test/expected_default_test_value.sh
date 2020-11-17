#!/bin/sh
../src/simbpf -c ../examples/default_test_value.sb | diff expected/default_test_value.txt -
