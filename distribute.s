#!/bin/bash
rsync -av remote/. root@servicesext:/ram/AWS/UDP-FEC/
rsync -av remote/. root@main2.accelcdn.com:bin/
#rsync -av remote/. root@172.16.10.102:bin/

