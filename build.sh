#!/bin/bash

mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=$1 -DTESTS=$2
make -j
