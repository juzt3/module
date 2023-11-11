#!/bin/bash

if [ -d "build" ]; then
  rm -rf ./build
fi

mkdir build
make all
cp src/n1.ko build/tmp
make clean
mv build/tmp build/n1.ko
