// SPDX-License-Identifier: MIT
package snesloader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.NoSuchElementException;

import ghidra.app.util.bin.ByteProvider;

/**
 * Iterates the ROM byte provider in fixed-size chunks (32 KiB for LoROM,
 * 64 KiB for HiROM). Each chunk knows both its provider offsets and its ROM
 * offsets (i.e. provider offset minus any SMC copier header).
 */
public class RomReader implements Iterable<RomReader.RomChunk> {

	private final RomInfo romInfo;
	private final ByteProvider provider;

	public RomReader(RomInfo romInfo, ByteProvider provider) {
		this.romInfo = romInfo;
		this.provider = provider;
	}

	@Override
	public Iterator<RomChunk> iterator() {
		return new RomChunkIterator();
	}

	private class RomChunkIterator implements Iterator<RomChunk> {
		private int nextChunkIdx = 0;

		private long chunkStart() {
			return romInfo.getStartOffset() + (long) nextChunkIdx * romInfo.getRomChunkSize();
		}

		private long chunkEnd() {
			return chunkStart() + romInfo.getRomChunkSize() - 1;
		}

		@Override
		public boolean hasNext() {
			return provider.isValidIndex(chunkEnd());
		}

		@Override
		public RomChunk next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			long start = chunkStart();
			long end = chunkEnd();
			nextChunkIdx++;
			return new RomChunk(start, end);
		}
	}

	public class RomChunk {
		private final long providerStartOffset;
		private final long providerEndOffset;
		private final long length;
		private byte[] bytes;

		public RomChunk(long providerStartOffset, long providerEndOffset) {
			this.providerStartOffset = providerStartOffset;
			this.providerEndOffset = providerEndOffset;
			this.length = (providerEndOffset - providerStartOffset) + 1;
		}

		public InputStream getInputStream() throws IOException {
			if (bytes == null) {
				bytes = provider.readBytes(providerStartOffset, length);
			}
			return new ByteArrayInputStream(bytes);
		}

		/** Provider-space offset (file-relative). */
		public long getProviderStart() { return providerStartOffset; }
		public long getProviderEnd() { return providerEndOffset; }

		/** ROM-space offset: same as provider, minus the SMC copier header. */
		public long getRomStart() {
			return providerStartOffset - romInfo.getStartOffset();
		}

		public long getRomEnd() {
			return providerEndOffset - romInfo.getStartOffset();
		}

		public long getLength() {
			return length;
		}
	}
}
