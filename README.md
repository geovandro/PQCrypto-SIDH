# Faster SIDH key compression is a fork of Microsoft's SIDH v2.0 library

Faster SIDH key compression introduces new algorithms to address the main (de)compression bottlenecks including the following contributions:
* faster basis generation for the 2^eA (~14x) and 3^eB torsions, 
* faster Tate pairing computation, 
* a faster algorithm for smooth-order discrete logarithms,
* a faster point tripling formula for the non-projective curve coefficient case,
* a reverse basis decomposition technique to avoid one pairing computation in each compression.


The related pre-print will appear soon on IACR ePrint Archive.


### Compilation options

There are two implementations of the prime field arithmetic in this library that can be enabled by using the ```ARCH_EX = [native|haswell|skylake]```
flag. 

 * Optimized for Haswell processors (append ARCH_EX=haswell):

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=FALSE SET=EXTENDED ASM=TRUE ARCH_EX=haswell
```

 * Optimized for Skylake processors (append ARCH_EX=skylake):

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=FALSE SET=EXTENDED ASM=TRUE ARCH_EX=skylake
```

 * Compile using the original prime field arithmetic.

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=FALSE SET=EXTENDED ASM=TRUE ARCH_EX=native
```

 * Compile for Apple OS.

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=[FALSE/TRUE] SET=EXTENDED [ASM=TRUE] [ARCH_EX=native] __APPLE__=TRUE
```

### License 
GNU Lesser General Public License v3.0 ([LICENSE](https://www.gnu.org/licenses/lgpl-3.0.txt))

