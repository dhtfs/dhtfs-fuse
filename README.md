# dhtfs-fuse

This package provides the dhtfs-fuse binary.

## Dependencies

* FUSE 2.9
* glib >= 2.40
* Apache Thrift >= 0.11

Apache Thrift is available in the repository of Debian 10.

In Ubuntu, it can be installed from the PPA: https://launchpad.net/~michal-ratajsky/+archive/ubuntu/dhtfs

## Installation

$ autoreconf -i

$ configure

$ make

$ sudo make install
