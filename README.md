libpcrypto
===================  


[![Author](https://img.shields.io/badge/made%20by-Francesco%20Pomp%C3%B2-blue.svg)](https://francesco.cc)
[![Build Status](https://travis-ci.org/pfrankw/libpcrypto.svg?branch=master)](https://travis-ci.org/pfrankw/libpcrypto)

What is it?
------------------
A generic crypto wrapper used in the C implementation of [libp2p](https://github.com/libp2p) for the [IPFS](https://ipfs.io) project.

Compiling
------------------

### Release build

    cmake . && make

### Debug build  

    cmake . -DCMAKE_BUILD_TYPE=DEBUG && make

TODO
------------------
- Add support for base32
- Write documentation
- Add specific error codes
