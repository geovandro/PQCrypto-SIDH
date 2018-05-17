# Faster SIDH key compression is a fork of SIDH v2.0 library

Faster SIDH key compression introduces new algorithms for speeding up the main SIDH (de)compression bottlenecks including the following contributions:
* faster basis generation for the 2^eA (~15.0x in compression and ~30x faster in decompression) and 3^eB torsions, 
* faster Tate pairing computation, 
* faster Pohlig-Hellman for smooth-order discrete logarithms inspired by the De Feo-Jao-Plut's optimal strategy,
* new windowed Pohlig-Hellman for cases where the window size w does not divide the exponent e
* faster point tripling formula for the non-projective curve coefficient case,
* reverse basis decomposition technique to avoid one pairing computation in each compression.
* new shared elligator for faster decompression in 3^eB (up to 2x faster) 
* shared elligator combined with entangled basis for generating the 2^eA-torsion achieves ~30x faster and breaks the 1M cycles barrier (0.83M cycles @Intel Core i5)



The related ePrint version is available [`here`](http://eprint.iacr.org/2017/1143).
The initial contributions of this work appeared in [1].

[1] [`Faster Isogeny-Based Compressed Key Agreement, PQCrypto 2018`](http://www.math.fau.edu/pqcrypto2018/accepted-papers.php).


### Compilation options

There are two implementations of the prime field arithmetic in this library that can be enabled by using the ```ARCH_EX = [native|haswell|skylake]```
flag. 

 * Optimized for Haswell processors (append ARCH_EX=haswell):

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=FALSE SET=EXTENDED ARCH_EX=haswell
```

 * Optimized for Skylake processors (append ARCH_EX=skylake):

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=FALSE SET=EXTENDED ARCH_EX=skylake
```

 * Compile using the original prime field arithmetic.

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=FALSE SET=EXTENDED ARCH_EX=native
```

 * Compile for Apple OSX.

```sh
$ make ARCH=x64 CC=[gcc/clang] GENERIC=[FALSE/TRUE] SET=EXTENDED ARCH_EX=native
```

### License 
GNU Lesser General Public License v3.0 ([LICENSE](https://www.gnu.org/licenses/lgpl-3.0.txt))

