import scala.scalanative.libc.stdlib
import scala.scalanative.libc.string
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

object ChaCha20 {
  val CHACHA20_KEY_SIZE = 32
  val CHACHA20_NONCE_SIZE = 12

  def xor(
      source: Array[UByte],
      key: Array[UByte],
      nonce: Array[UByte],
      counter: Int = 0
  ): Array[UByte] = {
    if (key.size != CHACHA20_KEY_SIZE)
      throw Exception(s"key size must be $CHACHA20_KEY_SIZE, not ${key.size}")
    if (nonce.size != CHACHA20_NONCE_SIZE)
      throw Exception(
        s"nonce size must be $CHACHA20_NONCE_SIZE, not ${nonce.size}"
      )

    Zone { implicit z =>
      {
        // inputs
        val sourceSize = source.size
        val sourcePtr = alloc[UByte](sourceSize).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until sourceSize) {
          !(sourcePtr + i) = source(i)
        }
        val keyPtr = alloc[UByte](CHACHA20_KEY_SIZE).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until CHACHA20_KEY_SIZE) {
          !(keyPtr + i) = key(i)
        }
        val noncePtr =
          alloc[UByte](CHACHA20_NONCE_SIZE).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until CHACHA20_NONCE_SIZE) {
          !(noncePtr + i) = nonce(i)
        }

        // output
        val destPtr = alloc[UByte](sourceSize).asInstanceOf[Ptr[UByte]]

        C_ChaCha20
          .chacha20_xor_stream(
            destPtr,
            sourcePtr,
            sourceSize.toULong,
            keyPtr,
            noncePtr,
            counter
          )

        // turn output into ubyte array
        val dest = Array.ofDim[UByte](sourceSize)
        for (i <- 0 until sourceSize) {
          dest(i) = (!(destPtr + i)).toUByte
        }

        dest
      }
    }
  }

  @extern
  object C_ChaCha20 {
    def chacha20_xor_stream(
        dest: Ptr[UByte],
        source: Ptr[UByte],
        length: CSize,
        key: Ptr[UByte],
        nonce: Ptr[UByte],
        counter: CInt
    ): Unit = extern;
  }
}
