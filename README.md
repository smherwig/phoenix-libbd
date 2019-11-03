Overview
========
libbd is a block device library for Phoenix SGX microkernel's
[nextfs](https://github.com/smherwig/phoenix-fileserver) filesystem.


Building and Installing
=======================
I will assume that sources are downloaded to `$HOME/src/` and that artifacts
are installed under `$HOME`.  libbd depends on [lwext4](https://github.com/gkostka/lwext4) and [librho](https://github.com/smherwig/librho).


First download and install lwext4.  I have a
[fork](https://github.com/smherwig/lwext4) of gkostka's lwext4 that adds
a `Makefile.smherwig` for the purpose of simplifying installation.

```
cd ~/src
git clone https://github.com/smherwig/lwext4
cd lwext4
make -f Makefile.smherwig
make -f Makefile.smherwig install INSTALL_TOP=$HOME
```


Next, download, build, and install
[librho](https://github.com/smherwig/librho):

```
git clone https:/github.com/smherwig/librho
cd librho/src
make
make install INSTALL_TOP=$HOME
```


Download, build, and install libbd:

```
cd ~/src
git clone https://github.com/smherwig/phoenix-libbd libbd
cd libbd
make
make install INSTALL_TOP=$HOME
```

The installation installs a static library, `libbd.a`, and header `bd.h`.
