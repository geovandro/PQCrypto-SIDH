# Faster SIDH key compression is a fork of SIDH v2.0 library

Faster SIDH key compression introduces new algorithms for speeding up the main SIDH (de)compression bottlenecks including the following contributions:
* faster basis generation for the 2^eA torsion (~15.0x faster compression and ~30x faster decompression) and the 3^eB torsion, 
* faster Tate pairing computation, 
* an O(e log e) Pohlig-Hellman strategy to compute smooth-order discrete logarithms. This is inspired by the De Feo-Jao-Plut's optimal strategy for smooth-degree isogenies,
* new windowed Pohlig-Hellman algorithm for window sizes w not dividing the exponent e on an l^e order discrete logarithm.
* faster point tripling formula for Montgomery curves with non-projective coefficients,
* reverse basis decomposition technique to avoid one pairing computation in each key compression.
* new shared elligator technique for faster decompression on both 2^eA and 3^eB torsions
* the shared elligator combined with entangled bases achieves ~30x faster 2^eA torsion basis generation and breaks the 1M cycles barrier (0.83M cycles @Intel Core i5-6267U). This costed ~23.8M cycles in previous work.



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

 * Compile for Apple MACOSX.

```sh
$ make ARCH=x64 CC=[gcc/clang] [MACOSX_CLANG=TRUE] GENERIC=[FALSE/TRUE] SET=EXTENDED ARCH_EX=native
```

### License 
GNU Lesser General Public License v3.0 ([LICENSE](https://www.gnu.org/licenses/lgpl-3.0.txt))

