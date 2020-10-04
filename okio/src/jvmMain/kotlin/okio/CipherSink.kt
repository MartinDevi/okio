/*
 * Copyright (C) 2020 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:JvmMultifileClass
@file:JvmName("Okio")

package okio

import java.io.IOException
import kotlin.math.min

private class CipherSink(
  private val sink: BufferedSink,
  private val cipher: BlockCipher
) : Sink {

  private val buffer = ByteArray(AESEngine.BLOCK_SIZE)
  private var bufferSize = 0

  private var closed = false

  @Throws(IOException::class)
  override fun write(source: Buffer, byteCount: Long) {
    checkOffsetAndCount(source.size, 0, byteCount)
    check(!closed) { "closed" }

    var remaining = byteCount
    while (remaining > 0) {
      val size = update(source, remaining)
      remaining -= size
    }
  }

  private fun update(source: Buffer, remaining: Long): Int {
    val head = source.head!!
    val headSize = min(head.limit - head.pos, remaining.toInt())

    if (bufferSize > 0) {
      // Buffer not empty, need to fill it
      val remainingBlock = AESEngine.BLOCK_SIZE - bufferSize
      if (headSize < remainingBlock) {
        // Can't complete a full block, copy into buffer what is available
        head.data.copyInto(buffer, bufferSize, head.pos, head.pos + headSize)
        source.head = head.pop()
        SegmentPool.recycle(head)
        bufferSize += headSize
        return headSize
      } else {
        // Complete full block and process
        head.data.copyInto(buffer, bufferSize, head.pos, head.pos + remainingBlock)
        bufferSize = 0

        val s = sink.buffer.writableSegment(AESEngine.BLOCK_SIZE)

        cipher.processBlock(buffer, 0, s.data, s.limit)
        s.limit += AESEngine.BLOCK_SIZE
        sink.buffer.size += AESEngine.BLOCK_SIZE

        source.size -= remainingBlock
        head.pos += remainingBlock

        if (head.pos == head.limit) {
          source.head = head.pop()
          SegmentPool.recycle(head)
        }

        return remainingBlock
      }
    }

    if (headSize < AESEngine.BLOCK_SIZE) {
      // Can't complete a full block, copy into buffer what is available
      head.data.copyInto(buffer, 0, head.pos, head.pos + headSize)
      bufferSize = headSize
      source.head = head.pop()
      SegmentPool.recycle(head)
      return headSize
    }

    // Process block directly from segment
    val s = sink.buffer.writableSegment(AESEngine.BLOCK_SIZE)

    cipher.processBlock(head.data, head.pos, s.data, s.limit)
    s.limit += AESEngine.BLOCK_SIZE
    sink.buffer.size += AESEngine.BLOCK_SIZE

    // Mark those bytes as read.
    source.size -= AESEngine.BLOCK_SIZE
    head.pos += AESEngine.BLOCK_SIZE

    if (head.pos == head.limit) {
      source.head = head.pop()
      SegmentPool.recycle(head)
    }

    return AESEngine.BLOCK_SIZE
  }

  override fun flush() =
    sink.flush()

  override fun timeout() =
    sink.timeout()

  @Throws(IOException::class)
  override fun close() {
    if (closed) return
    closed = true

    var thrown: Throwable? = doFinal()

    try {
      sink.close()
    } catch (e: Throwable) {
      if (thrown == null) thrown = e
    }

    if (thrown != null) throw thrown
  }

  private fun doFinal(): Throwable? {
    if (bufferSize == 0) return null

    // Add PKCS7 padding
    val code = (AESEngine.BLOCK_SIZE - bufferSize).toByte()
    buffer.fill(code, bufferSize, AESEngine.BLOCK_SIZE)

    val s = sink.buffer.writableSegment(AESEngine.BLOCK_SIZE)

    try {
      cipher.processBlock(buffer, 0, s.data, s.limit)

      s.limit += AESEngine.BLOCK_SIZE
      sink.buffer.size += AESEngine.BLOCK_SIZE
    } catch (e: Throwable) {
      return e
    }

    return null
  }
}

/**
 * Returns a [Sink] that processes data using this [BlockCipher] while writing to
 * [sink].
 *
 * @throws IllegalArgumentException
 *  If this isn't a block cipher.
 */
fun BlockCipher.sink(sink: BufferedSink): Sink =
  CipherSink(sink, this)
