#!/bin/bash
rsync -av . root@omnitrain:/ram/AWS/UDP-FEC/src/
ssh root@omnitrain make -C /ram/AWS/UDP-FEC/src
