#!/bin/bash

# example
# growing on the number of processes 
./test.sh 128 4096 1 1
./test.sh 128 4096 2 1
./test.sh 128 4096 4 1

# growing on the number of objects
./test.sh 128 4096 1 1
./test.sh 512 4096 1 1
./test.sh 1024 4096 1 1
./test.sh 4096 4096 1 1

# growing on the object size
./test.sh 128 4096 1 1
./test.sh 128 8192 1 1

# growing on the number of containers
./test.sh 128 4096 2 2
./test.sh 128 4096 8 8
./test.sh 128 4096 64 64

# combination
./test.sh 256 8192 8 4
