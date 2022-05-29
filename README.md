sn-chacha20poly1305
===================

ChaCha20 + Poly1305 Authenticated Encryption with Associated Data (AEAD) ([RFC-8439](https://github.com/DavyLandman/portable8439)) implementation in C for use in Scala 3 Native.
C code copied from https://github.com/DavyLandman/portable8439.

Installation
------------

```sbt
libraryDependencies += "com.fiatjaf" %%% "sn-chacha20poly1305" % "0.1.0"
```

Usage
-----

This library provides 2 functions: `encrypt` and `decrypt`:

```scala
import scala.scalanative.unsigned._
import chacha20poly1305.{encrypt, decrypt}

val ciphertext: Array[UByte] = encrypt(
  Array.fill[UByte](8)(0.toUByte),
  Array.fill[UByte](32)(0.toUByte),
  Array.fill[UByte](12)(0.toUByte)
)
bytes2hex(x) ==> "9f07e7be5551387a82035dc15bf3f97201764a1eb16e3aa2"

val d = decrypt(
  hex2bytes("9f07e7be5551387a82035dc15bf3f97201764a1eb16e3aa2"),
  Array.fill[UByte](32)(0.toUByte),
  Array.fill[UByte](12)(0.toUByte)
)
bytes2hex(d.get) ==> "0000000000000000"
```

There is also an optional `associatedData` argument to both `encrypt` and `decrypt`. See [scaladoc](https://www.javadoc.io/doc/com.fiatjaf/sn-chacha20poly1305_native0.4_3/latest/index.html).
