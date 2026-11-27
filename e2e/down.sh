#!/usr/bin/env bash
docker rm -f $(docker ps -aq --filter name='^vps[0-9]+$') 2>/dev/null
docker network rm vpsnet 2>/dev/null
rm -rf /tmp/latrix-e2e
