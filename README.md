sn-chacha20poly1305
===================

_ChaCha20_ stream cipher and
_ChaCha20+Poly1305 AEAD_ (Authenticated Encryption with Associated Data) ([RFC-8439](https://github.com/DavyLandman/portable8439)) implementations in C for use in Scala 3 Native.

C code copied from https://github.com/DavyLandman/portable8439.

Installation
------------

```sbt
libraryDependencies += "com.fiatjaf" %%% "sn-chacha20poly1305" % "0.2.1"
```

Usage
-----

This library provides an object `ChaCha20Poly1305` with 2 functions, `encrypt` and `decrypt`;
and an object `ChaCha20` with a single function `xor`. See example usage below:

```scala
import scala.scalanative.unsigned._
import ChaCha20Poly1305.{encrypt, decrypt}
import ChaCha20.{xor}

// chacha20
bytes2hex(
  xor(
    Array.fill[UByte](64)(0.toUByte),
    Array.fill[UByte](32)(0.toUByte),
    Array.fill[UByte](12)(0.toUByte)
  )
) ==> "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"

// chacha20poly1305
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

There is also an optional `associatedData` argument to both `encrypt` and `decrypt` and a `counter` argument to `xor`. See [Scaladoc](https://www.javadoc.io/doc/com.fiatjaf/sn-chacha20poly1305_native0.4_3/latest/index.html).
