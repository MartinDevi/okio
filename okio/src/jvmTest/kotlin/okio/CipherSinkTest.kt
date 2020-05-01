package okio

import org.junit.Test
import kotlin.random.Random

class CipherSinkTest {

  @Test
  fun encryptWithClose() {
    val random = Random(1588326457426L)
    val data = random.nextBytes(32)
    val key = random.nextBytes(16)
    val cipherFactory = CipherFactory(key)

    val buffer = Buffer()
    buffer.cipherSink(cipherFactory.encrypt).buffer().use { it.write(data) }
    val actualEncryptedData = buffer.readByteArray()

    val expectedEncryptedData = cipherFactory.encrypt.doFinal(data)
    assertArrayEquals(expectedEncryptedData, actualEncryptedData)
  }

  @Test
  fun decryptWithClose() {
    val random = Random(1588326610176L)
    val key = random.nextBytes(16)
    val cipherFactory = CipherFactory(key)
    val expectedData = random.nextBytes(32)
    val encryptedData = cipherFactory.encrypt.doFinal(expectedData)

    val buffer = Buffer()
    buffer.cipherSink(cipherFactory.decrypt).buffer().use { it.write(encryptedData) }
    val actualData = buffer.readByteArray()

    assertArrayEquals(expectedData, actualData)
  }
}
