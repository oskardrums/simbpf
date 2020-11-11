#!/bin/sh
docker run -v /home/user/checkouts/simbpf/tst:/tst -v /usr:/usr -u root -it debian /tst/test_simbpf
