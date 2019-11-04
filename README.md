Overview
========
libbd is a block device library for
[Phoenix](https://github.com/smherwig/phoenix) SGX microkernel's
[nextfs](https://github.com/smherwig/phoenix-fileserver) filesystem.


<a name="building"/> Building and Installing
============================================
libbd depends on [librho](https://github.com/smherwig/librho) and
[lwext4](https://github.com/gkostka/lwext4).  The
instructions here assume that both are installed under `$HOME`.
 I have a [fork](https://github.com/smherwig/lwext4) of gkostka's lwext4 that adds
a `Makefile.smherwig` for the purpose of simplifying lwext4's installation.

```
cd ~/src
git clone https://github.com/smherwig/lwext4
cd lwext4
make -f Makefile.smherwig
make -f Makefile.smherwig install INSTALL_TOP=$HOME
```

Next, Download, build, and install libbd:

```
cd ~/src
git clone https://github.com/smherwig/phoenix-libbd libbd
cd libbd
make
make install INSTALL_TOP=$HOME
```

The installation installs a static library, `libbd.a`, and header `bd.h`.
