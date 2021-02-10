#!/bin/bash
docker rm -f ti1337plusce
docker run --rm --name ti1337plusce -p 31337:1337 ti1337plusce &
