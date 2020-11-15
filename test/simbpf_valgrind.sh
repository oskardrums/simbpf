#!/bin/sh
valgrind --leak-check=full --error-exitcode=1 ./test_simbpf < ../src/input.txt
