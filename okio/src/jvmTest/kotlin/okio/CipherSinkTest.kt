package okio

import org.junit.Test
import kotlin.random.Random

class CipherSinkTest {

  @Test
  fun encryptEcb() {
    val random = Random(8912860393601532863)
    val cipherFactory = CipherAlgorithm("AES/ECB/NoPadding", false, 16).createCipherFactory(random)
    val data = random.nextBytes(32)

    val buffer = Buffer()
    AESEngine().apply { init(true, KeyParameter(cipherFactory.key)) }.sink(buffer).buffer().use { it.write(data) }
    val actualEncryptedData = buffer.readByteArray()

    val expectedEncryptedData = cipherFactory.encrypt.doFinal(data)
    assertArrayEquals(expectedEncryptedData, actualEncryptedData)
  }


  @Test
  fun encryptCbc() {
    val random = Random(8912860393601532863)
    val cipherFactory = CipherAlgorithm("AES/CBC/NoPadding", false, 16, 16).createCipherFactory(random)
    val data = random.nextBytes(128)

    val buffer = Buffer()
    CBCBlockCipher(AESEngine()).apply { init(true, ParametersWithIV(KeyParameter(cipherFactory.key), cipherFactory.iv)) }.sink(buffer).buffer().use { it.write(data) }
    val actualEncryptedData = buffer.readByteArray()

    val expectedEncryptedData = cipherFactory.encrypt.doFinal(data)
    assertArrayEquals(expectedEncryptedData, actualEncryptedData)
  }

  @Test
  fun encryptCbcPaddedPkcs7() {
    val random = Random(8912860393601532863)
    val cipherFactory = CipherAlgorithm("AES/CBC/PKCS5Padding", false, 16, 16).createCipherFactory(random)
    val data = random.nextBytes(124)

    val buffer = Buffer()
    CBCBlockCipher(AESEngine()).apply { init(true, ParametersWithIV(KeyParameter(cipherFactory.key), cipherFactory.iv)) }.sink(buffer).buffer().use { it.write(data) }
    val actualEncryptedData = buffer.readByteArray()

    val expectedEncryptedData = cipherFactory.encrypt.doFinal(data)
    assertArrayEquals(expectedEncryptedData, actualEncryptedData)
  }
}
