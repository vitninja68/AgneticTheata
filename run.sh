#!/usr/bin/env sh
docker build . -t watninja68/theataagent
docker run --rm --network host -e HOST="0.0.0.0" watninja68/theataagent
