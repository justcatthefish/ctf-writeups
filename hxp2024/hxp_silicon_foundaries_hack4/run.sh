#!/bin/sh
set -e

cd example_program
./build.sh
cp exploit ../unpacked/e
cp crash ../unpacked/crash
cd ..
./pack.sh
sudo docker compose up --build
