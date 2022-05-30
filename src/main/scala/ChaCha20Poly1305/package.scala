import scala.scalanative.libc.stdlib
import scala.scalanative.libc.string
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

package object ChaCha20Poly1305 {
  val RFC_8439_TAG_SIZE = 16
  val RFC_8439_NONCE_SIZE = 12
  val RFC_8439_KEY_SIZE = 32

  def encrypt(
      plaintext: Array[UByte],
      key: Array[UByte],
      nonce: Array[UByte],
      associatedData: Array[UByte] = Array.empty
  ): Array[UByte] = {
    if (key.size != RFC_8439_KEY_SIZE)
      throw Exception(s"key size must be $RFC_8439_KEY_SIZE, not ${key.size}")
    if (nonce.size != RFC_8439_NONCE_SIZE)
      throw Exception(
        s"nonce size must be $RFC_8439_NONCE_SIZE, not ${nonce.size}"
      )

    Zone { implicit z =>
      {
        // inputs
        val plaintextSize = plaintext.size
        val plaintextPtr = alloc[UByte](plaintextSize).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until plaintextSize) {
          !(plaintextPtr + i) = plaintext(i)
        }
        val keyPtr = alloc[UByte](RFC_8439_KEY_SIZE).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until RFC_8439_KEY_SIZE) {
          !(keyPtr + i) = key(i)
        }
        val noncePtr =
          alloc[UByte](RFC_8439_NONCE_SIZE).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until RFC_8439_NONCE_SIZE) {
          !(noncePtr + i) = nonce(i)
        }
        val associatedDataSize = associatedData.size
        val associatedDataPtr =
          alloc[UByte](associatedDataSize).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until associatedDataSize) {
          !(associatedDataPtr + i) = associatedData(i)
        }

        // output
        val ciphertextPtr =
          alloc[UByte](plaintextSize + RFC_8439_TAG_SIZE)
            .asInstanceOf[Ptr[UByte]]

        val ciphertextSize = C_ChaCha20Poly1305
          .portable_chacha20_poly1305_encrypt(
            ciphertextPtr,
            keyPtr,
            noncePtr,
            associatedDataPtr,
            associatedDataSize.toULong,
            plaintextPtr,
            plaintextSize.toULong
          )
          .toInt

        // turn output into ubyte array
        val ciphertext = Array.ofDim[UByte](ciphertextSize)
        for (i <- 0 until ciphertextSize) {
          ciphertext(i) = (!(ciphertextPtr + i)).toUByte
        }

        ciphertext
      }
    }
  }

  def decrypt(
      ciphertext: Array[UByte],
      key: Array[UByte],
      nonce: Array[UByte],
      associatedData: Array[UByte] = Array.empty
  ): Option[Array[UByte]] = {
    if (ciphertext.size <= RFC_8439_TAG_SIZE)
      throw Exception(
        s"ciphertext size must be greater than $RFC_8439_TAG_SIZE, not ${ciphertext.size}"
      )
    if (key.size != RFC_8439_KEY_SIZE)
      throw Exception(s"key size must be $RFC_8439_KEY_SIZE, not ${key.size}")
    if (nonce.size != RFC_8439_NONCE_SIZE)
      throw Exception(
        s"nonce size must be $RFC_8439_NONCE_SIZE, not ${nonce.size}"
      )

    Zone { implicit z =>
      {
        // inputs
        val ciphertextSize = ciphertext.size
        val ciphertextPtr =
          alloc[UByte](ciphertextSize).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until ciphertextSize) {
          !(ciphertextPtr + i) = ciphertext(i)
        }
        val keyPtr = alloc[UByte](RFC_8439_KEY_SIZE).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until RFC_8439_KEY_SIZE) {
          !(keyPtr + i) = key(i)
        }
        val noncePtr =
          alloc[UByte](RFC_8439_NONCE_SIZE).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until RFC_8439_NONCE_SIZE) {
          !(noncePtr + i) = nonce(i)
        }
        val associatedDataSize = associatedData.size
        val associatedDataPtr =
          alloc[UByte](associatedDataSize).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until associatedDataSize) {
          !(associatedDataPtr + i) = associatedData(i)
        }

        // output
        val plaintextPtr = alloc[UByte](ciphertextSize - RFC_8439_TAG_SIZE)
          .asInstanceOf[Ptr[UByte]]

        val plaintextSize = C_ChaCha20Poly1305
          .portable_chacha20_poly1305_decrypt(
            plaintextPtr,
            keyPtr,
            noncePtr,
            associatedDataPtr,
            associatedDataSize.toULong,
            ciphertextPtr,
            ciphertextSize.toULong
          )
          .toInt

        if plaintextSize == -1 then { None }
        else {
          // turn output into ubyte array
          val plaintext = Array.ofDim[UByte](plaintextSize)
          for (i <- 0 until plaintextSize) {
            plaintext(i) = (!(plaintextPtr + i)).toUByte
          }

          Some(plaintext)
        }
      }
    }
  }

  @extern
  object C_ChaCha20Poly1305 {
    def portable_chacha20_poly1305_encrypt(
        cipher_text: Ptr[UByte],
        key: Ptr[UByte],
        nonce: Ptr[UByte],
        ad: Ptr[UByte],
        ad_size: CSize,
        plain_text: Ptr[UByte],
        plain_text_size: CSize
    ): CSize = extern

    def portable_chacha20_poly1305_decrypt(
        plain_text: Ptr[UByte],
        key: Ptr[UByte],
        nonce: Ptr[UByte],
        ad: Ptr[UByte],
        ad_size: CSize,
        cipher_text: Ptr[UByte],
        cipher_text_size: CSize
    ): CSize = extern
  }
}
