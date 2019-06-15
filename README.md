# dhtfs-fuse

This package provides `dhtfs-fuse`, the DHTFS user-space file system binary.

The software was developed on Debian Buster and also (in a limited way) tested on Ubuntu 19.04.

## Dependencies

* FUSE 2.9
* glib >= 2.40
* Apache Thrift >= 0.11
* libbtrfsutil

Apache Thrift is available in the repository of Debian 10.

In Ubuntu, it can be installed from the PPA: https://launchpad.net/~michal-ratajsky/+archive/ubuntu/dhtfs

The following command should install all necessary development packages on a Debian/Ubuntu system:

`sudo apt install build-essential autoconf pkg-config libfuse-dev libglib2.0-dev libthrift-c-glib-dev libbtrfsutil-dev`

## Installation

The package uses the standard autotools build system.

```
$ autoreconf -i
$ ./configure
$ make
$ sudo make install
```

## Usage

The program requires at least one running DHT node with a file system recorded in it. These steps are described in the [dhtfs](https://github.com/dhtfs/dhtfs) README file. It should be run using the `dhtfs mount` wrapper, but can be also used without it (see `dhtfs-fuse -h`).
