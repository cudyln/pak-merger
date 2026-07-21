use crate::{Error, Hash};

#[cfg(feature = "compression")]
use crate::data::{
    compression_block_layout, get_compression_slot, write_compressed_blocks_with_progress,
};

use super::{ext::BoolExt, ext::ReadExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum EntryLocation {
    Data,
    Index,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Block {
    pub start: u64,
    pub end: u64,
}

impl Block {
    pub fn read<R: io::Read>(reader: &mut R) -> Result<Self, super::Error> {
        Ok(Self {
            start: reader.read_u64::<LE>()?,
            end: reader.read_u64::<LE>()?,
        })
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        writer.write_u64::<LE>(self.start)?;
        writer.write_u64::<LE>(self.end)?;
        Ok(())
    }
}

fn align(offset: u64) -> u64 {
    // add alignment (aes block size: 16) then zero out alignment bits
    (offset + 15) & !15
}

#[cfg(feature = "compression")]
#[derive(Debug, Clone, Copy)]
struct CompressedBlock {
    file_offset: u64,
    compressed_size: u64,
    uncompressed_size: usize,
}

#[cfg(feature = "compression")]
fn allocation_buffer(size: usize, compression: Compression) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(size).map_err(|_| {
        Error::Other(format!(
            "could not allocate a {size}-byte {compression:?} block buffer"
        ))
    })?;
    buffer.resize(size, 0);
    Ok(buffer)
}

#[cfg(feature = "compression")]
fn read_block<R: io::Read + io::Seek>(
    reader: &mut R,
    block: CompressedBlock,
    compression: Compression,
) -> Result<Vec<u8>, Error> {
    let compressed_size = usize::try_from(block.compressed_size)
        .map_err(|_| Error::DecompressionFailed(compression))?;
    let mut data = allocation_buffer(compressed_size, compression)?;
    reader.seek(io::SeekFrom::Start(block.file_offset))?;
    reader.read_exact(&mut data)?;
    Ok(data)
}

/// Restricts a streaming decoder to exactly one declared Pak block.
///
/// Besides validating the block boundary, this prevents a corrupt compressed
/// stream from sending data belonging to a later block to the caller.
#[cfg(feature = "compression")]
struct ExactBlockWriter<'a, W> {
    inner: &'a mut W,
    remaining: u64,
}

#[cfg(feature = "compression")]
impl<'a, W> ExactBlockWriter<'a, W> {
    fn new(inner: &'a mut W, expected: usize) -> Self {
        Self {
            inner,
            remaining: expected as u64,
        }
    }

    fn finish(self, compression: Compression) -> Result<(), Error> {
        if self.remaining == 0 {
            Ok(())
        } else {
            Err(Error::DecompressionFailed(compression))
        }
    }
}

#[cfg(feature = "compression")]
impl<W: io::Write> io::Write for ExactBlockWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let allowed = usize::try_from(self.remaining.min(data.len() as u64))
            .expect("the allowed write length is bounded by the input slice");
        if allowed == 0 && !data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded block is larger than its declared size",
            ));
        }
        let written = self.inner.write(&data[..allowed])?;
        self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn compression_index_size(version: Version) -> CompressionIndexSize {
    match version {
        Version::V8A => CompressionIndexSize::U8,
        _ => CompressionIndexSize::U32,
    }
}

enum CompressionIndexSize {
    U8,
    U32,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Entry {
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression_slot: Option<u32>,
    pub timestamp: Option<u64>,
    pub hash: Option<Hash>,
    pub blocks: Option<Vec<Block>>,
    pub flags: u8,
    pub compression_block_size: u32,
}

impl Entry {
    pub fn is_encrypted(&self) -> bool {
        0 != (self.flags & 1)
    }
    pub fn is_deleted(&self) -> bool {
        0 != (self.flags >> 1) & 1
    }
    pub fn get_serialized_size(
        version: super::Version,
        compression: Option<u32>,
        block_count: u32,
    ) -> u64 {
        let mut size = 0;
        size += 8; // offset
        size += 8; // compressed
        size += 8; // uncompressed
        size += match compression_index_size(version) {
            CompressionIndexSize::U8 => 1,  // 8 bit compression
            CompressionIndexSize::U32 => 4, // 32 bit compression
        };
        size += match version.version_major() == VersionMajor::Initial {
            true => 8, // timestamp
            false => 0,
        };
        size += 20; // hash
        size += match compression {
            Some(_) => 4 + (8 + 8) * block_count as u64, // blocks
            None => 0,
        };
        size += 1; // encrypted
        size += match version.version_major() >= VersionMajor::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }

    pub(crate) fn write_file<W, P>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        allowed_compression: &[Compression],
        parallel_blocks: bool,
        data: &[u8],
        progress: &mut P,
    ) -> Result<Self, Error>
    where
        W: io::Write + io::Seek,
        P: FnMut(u64, u64) -> bool,
    {
        Self::write_file_with_source_chunks(
            writer,
            version,
            compression_slots,
            allowed_compression,
            parallel_blocks,
            data,
            (progress, &mut |_| {}),
        )
    }

    pub(crate) fn write_file_with_source_chunks<W, P, S>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        allowed_compression: &[Compression],
        parallel_blocks: bool,
        data: &[u8],
        callbacks: (&mut P, &mut S),
    ) -> Result<Self, Error>
    where
        W: io::Write + io::Seek,
        P: FnMut(u64, u64) -> bool,
        S: FnMut(&[u8]),
    {
        let (progress, source_chunks) = callbacks;
        if allowed_compression.is_empty() {
            return Self::write_uncompressed_file(writer, version, data, progress, source_chunks);
        }

        #[cfg(not(feature = "compression"))]
        unreachable!("compression cannot be selected without the compression feature");
        #[cfg(feature = "compression")]
        return Self::write_compressed_file(
            writer,
            version,
            compression_slots,
            *allowed_compression
                .first()
                .expect("non-empty compression list was checked above"),
            parallel_blocks,
            data,
            (progress, source_chunks),
        );
    }

    /// Writes compressed blocks directly to the Pak and backpatches the fixed
    /// size entry header afterward. Each source block is compressed once, and
    /// only a bounded number of ordered results can be in flight.
    #[cfg(feature = "compression")]
    fn write_compressed_file<W, P, S>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        compression: Compression,
        parallel_blocks: bool,
        data: &[u8],
        callbacks: (&mut P, &mut S),
    ) -> Result<Self, Error>
    where
        W: io::Write + io::Seek,
        P: FnMut(u64, u64) -> bool,
        S: FnMut(&[u8]),
    {
        let (progress, source_chunks) = callbacks;
        if data.is_empty() {
            return Self::write_uncompressed_file(writer, version, data, progress, source_chunks);
        }

        let mut completed = 0_u64;
        let total = data.len() as u64;
        if !progress(0, total) {
            return Err(Error::Other("operation cancelled".to_owned()));
        }
        let mut update = |delta: u64| {
            completed = completed.saturating_add(delta);
            progress(completed, total)
        };

        let layout = compression_block_layout(total)?;
        let block_count = usize::try_from(layout.block_count)
            .map_err(|_| Error::Other("compression block count does not fit usize".to_owned()))?;
        let compression_slot = get_compression_slot(version, compression_slots, compression)?;
        let stream_position = writer.stream_position()?;
        let mut entry = Entry {
            offset: stream_position,
            compressed: 0,
            uncompressed: total,
            compression_slot: Some(compression_slot),
            timestamp: None,
            hash: Some(Hash::default()),
            blocks: Some(vec![Block::default(); block_count]),
            flags: 0,
            compression_block_size: layout.block_size,
        };
        entry.write(writer, version, EntryLocation::Data)?;
        let data_start = writer.stream_position()?;

        let compressed = write_compressed_blocks_with_progress(
            writer,
            compression,
            parallel_blocks,
            layout.block_size,
            data,
            &mut update,
            source_chunks,
        )?;
        debug_assert_eq!(compressed.block_sizes.len(), block_count);
        let data_end = writer.stream_position()?;

        let mut block_offset = if version.version_major() < VersionMajor::RelativeChunkOffsets {
            data_start
        } else {
            data_start.checked_sub(stream_position).ok_or_else(|| {
                Error::Other("compressed entry data starts before its header".to_owned())
            })?
        };
        for (block, size) in entry
            .blocks
            .as_mut()
            .expect("compressed entry always has block metadata")
            .iter_mut()
            .zip(compressed.block_sizes)
        {
            block.start = block_offset;
            block_offset = block_offset
                .checked_add(size)
                .ok_or_else(|| Error::Other("compressed block offset overflowed".to_owned()))?;
            block.end = block_offset;
        }
        entry.compressed = compressed.compressed_size;
        entry.hash = Some(compressed.hash);

        writer.seek(io::SeekFrom::Start(stream_position))?;
        entry.write(writer, version, EntryLocation::Data)?;
        writer.seek(io::SeekFrom::Start(data_end))?;
        Ok(entry)
    }

    /// Writes and hashes an uncompressed payload in a single source pass.
    ///
    /// The data header is emitted with a temporary hash, then only that small
    /// header is patched after the payload has been copied. The source bytes
    /// are never revisited, and the final bytes are identical to the former
    /// pre-hash-then-write path.
    fn write_uncompressed_file<W, P, S>(
        writer: &mut W,
        version: Version,
        data: &[u8],
        progress: &mut P,
        source_chunks: &mut S,
    ) -> Result<Self, Error>
    where
        W: io::Write + io::Seek,
        P: FnMut(u64, u64) -> bool,
        S: FnMut(&[u8]),
    {
        use sha1::{Digest, Sha1};

        let stream_position = writer.stream_position()?;
        let size = data.len() as u64;
        let mut entry = Entry {
            offset: stream_position,
            compressed: size,
            uncompressed: size,
            compression_slot: None,
            timestamp: None,
            hash: Some(Hash::default()),
            blocks: None,
            flags: 0,
            compression_block_size: 0,
        };
        entry.write(writer, version, EntryLocation::Data)?;

        let mut hasher = Sha1::new();
        let mut completed = 0_u64;
        if !progress(0, size) {
            return Err(Error::Other("operation cancelled".to_owned()));
        }
        for chunk in data.chunks(4 * 1024 * 1024) {
            hasher.update(chunk);
            writer.write_all(chunk)?;
            source_chunks(chunk);
            completed = completed.saturating_add(chunk.len() as u64);
            if !progress(completed, size) {
                return Err(Error::Other("operation cancelled".to_owned()));
            }
        }
        let data_end = writer.stream_position()?;

        entry.hash = Some(Hash(hasher.finalize().into()));
        writer.seek(io::SeekFrom::Start(stream_position))?;
        entry.write(writer, version, EntryLocation::Data)?;
        writer.seek(io::SeekFrom::Start(data_end))?;
        Ok(entry)
    }

    pub fn read<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let ver = version.version_major();
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression = match match compression_index_size(version) {
            CompressionIndexSize::U8 => reader.read_u8()? as u32,
            CompressionIndexSize::U32 => reader.read_u32::<LE>()?,
        } {
            0 => None,
            n => Some(n - 1),
        };
        let timestamp = (ver == VersionMajor::Initial).then_try(|| reader.read_u64::<LE>())?;
        let hash = Some(Hash(reader.read_guid()?));
        let blocks = (ver >= VersionMajor::CompressionEncryption && compression.is_some())
            .then_try(|| ReadExt::read_array(reader, Block::read))?;
        let flags = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u8())?
            .unwrap_or(0);
        let compression_block_size = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u32::<LE>())?
            .unwrap_or(0);
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression_slot: compression,
            timestamp,
            hash,
            blocks,
            flags,
            compression_block_size,
        })
    }

    pub fn write<W: io::Write>(
        &self,
        writer: &mut W,
        version: super::Version,
        location: EntryLocation,
    ) -> Result<(), super::Error> {
        writer.write_u64::<LE>(match location {
            EntryLocation::Data => 0,
            EntryLocation::Index => self.offset,
        })?;
        writer.write_u64::<LE>(self.compressed)?;
        writer.write_u64::<LE>(self.uncompressed)?;
        let compression = self.compression_slot.map_or(0, |n| n + 1);
        match compression_index_size(version) {
            CompressionIndexSize::U8 => writer.write_u8(compression.try_into().unwrap())?,
            CompressionIndexSize::U32 => writer.write_u32::<LE>(compression)?,
        }

        if version.version_major() == VersionMajor::Initial {
            writer.write_u64::<LE>(self.timestamp.unwrap_or_default())?;
        }
        if let Some(hash) = self.hash {
            writer.write_all(&hash.0)?;
        } else {
            panic!("hash missing");
        }
        if version.version_major() >= VersionMajor::CompressionEncryption {
            if let Some(blocks) = &self.blocks {
                writer.write_u32::<LE>(blocks.len() as u32)?;
                for block in blocks {
                    block.write(writer)?;
                }
            }
            writer.write_u8(self.flags)?;
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        Ok(())
    }

    pub fn read_encoded<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let bits = reader.read_u32::<LE>()?;
        let compression = match (bits >> 23) & 0x3f {
            0 => None,
            n => Some(n - 1),
        };

        let encrypted = (bits & (1 << 22)) != 0;
        let compression_block_count: u32 = (bits >> 6) & 0xffff;
        let mut compression_block_size = bits & 0x3f;

        if compression_block_size == 0x3f {
            compression_block_size = reader.read_u32::<LE>()?;
        } else {
            compression_block_size <<= 11;
        }

        let mut var_int = |bit: u32| -> Result<_, super::Error> {
            Ok(if (bits & (1 << bit)) != 0 {
                reader.read_u32::<LE>()? as u64
            } else {
                reader.read_u64::<LE>()?
            })
        };

        let offset = var_int(31)?;
        let uncompressed = var_int(30)?;
        let compressed = match compression {
            None => uncompressed,
            _ => var_int(29)?,
        };

        let offset_base = Entry::get_serialized_size(version, compression, compression_block_count);

        let blocks = if compression_block_count == 1 && !encrypted {
            Some(vec![Block {
                start: offset_base,
                end: offset_base + compressed,
            }])
        } else if compression_block_count > 0 {
            let mut index = offset_base;
            Some(
                (0..compression_block_count)
                    .map(|_| {
                        let mut block_size = reader.read_u32::<LE>()? as u64;
                        let block = Block {
                            start: index,
                            end: index + block_size,
                        };
                        if encrypted {
                            block_size = align(block_size);
                        }
                        index += block_size;
                        Ok(block)
                    })
                    .collect::<Result<Vec<_>, super::Error>>()?,
            )
        } else {
            None
        };

        Ok(Entry {
            offset,
            compressed,
            uncompressed,
            timestamp: None,
            compression_slot: compression,
            hash: None,
            blocks,
            flags: encrypted as u8,
            compression_block_size,
        })
    }

    pub fn write_encoded<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        let mut compression_block_size = (self.compression_block_size >> 11) & 0x3f;
        if (compression_block_size << 11) != self.compression_block_size {
            compression_block_size = 0x3f;
        }
        let compression_blocks_count = if self.compression_slot.is_some() {
            u32::try_from(self.blocks.as_ref().unwrap().len()).map_err(|_| {
                super::Error::Other("compression block count does not fit u32".to_owned())
            })?
        } else {
            0
        };
        let is_size_32_bit_safe = self.compressed <= u32::MAX as u64;
        let is_uncompressed_size_32_bit_safe = self.uncompressed <= u32::MAX as u64;
        let is_offset_32_bit_safe = self.offset <= u32::MAX as u64;

        if compression_blocks_count > crate::MAX_COMPRESSION_BLOCKS {
            return Err(super::Error::Other(format!(
                "compression block count {compression_blocks_count} exceeds the Pak v11 limit of {}",
                crate::MAX_COMPRESSION_BLOCKS
            )));
        }

        let flags = (compression_block_size)
            | (compression_blocks_count << 6)
            | ((self.is_encrypted() as u32) << 22)
            | (self.compression_slot.map_or(0, |n| n + 1) << 23)
            | ((is_size_32_bit_safe as u32) << 29)
            | ((is_uncompressed_size_32_bit_safe as u32) << 30)
            | ((is_offset_32_bit_safe as u32) << 31);

        writer.write_u32::<LE>(flags)?;

        if compression_block_size == 0x3f {
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        if is_offset_32_bit_safe {
            writer.write_u32::<LE>(self.offset as u32)?;
        } else {
            writer.write_u64::<LE>(self.offset)?;
        }

        if is_uncompressed_size_32_bit_safe {
            writer.write_u32::<LE>(self.uncompressed as u32)?
        } else {
            writer.write_u64::<LE>(self.uncompressed)?
        }

        if self.compression_slot.is_some() {
            if is_size_32_bit_safe {
                writer.write_u32::<LE>(self.compressed as u32)?;
            } else {
                writer.write_u64::<LE>(self.compressed)?;
            }

            assert!(self.blocks.is_some());
            let blocks = self.blocks.as_ref().unwrap();
            if blocks.len() > 1 || self.is_encrypted() {
                for b in blocks {
                    let block_size = b.end - b.start;
                    let block_size = u32::try_from(block_size).map_err(|_| {
                        super::Error::Other(
                            "stored compression block size does not fit u32".to_owned(),
                        )
                    })?;
                    writer.write_u32::<LE>(block_size)?;
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "compression")]
    fn compressed_blocks(
        &self,
        version: Version,
        data_offset: u64,
        compression: Compression,
    ) -> Result<Vec<CompressedBlock>, Error> {
        if self.uncompressed == 0 {
            if self.compressed != 0
                || self
                    .blocks
                    .as_ref()
                    .is_some_and(|blocks| !blocks.is_empty())
            {
                return Err(Error::DecompressionFailed(compression));
            }
            return Ok(Vec::new());
        }

        let Some(index_blocks) = &self.blocks else {
            return Ok(vec![CompressedBlock {
                file_offset: data_offset,
                compressed_size: self.compressed,
                uncompressed_size: usize::try_from(self.uncompressed)
                    .map_err(|_| Error::DecompressionFailed(compression))?,
            }]);
        };

        let logical_block_size = u64::from(self.compression_block_size);
        if logical_block_size == 0 {
            return Err(Error::DecompressionFailed(compression));
        }
        let expected_count = self.uncompressed.div_ceil(logical_block_size);
        if u64::try_from(index_blocks.len()).ok() != Some(expected_count) {
            return Err(Error::DecompressionFailed(compression));
        }

        let relative_offsets = version.version_major() >= VersionMajor::RelativeChunkOffsets;
        let mut logical_remaining = self.uncompressed;
        let mut stored_total = 0_u64;
        let mut blocks = Vec::with_capacity(index_blocks.len());
        for block in index_blocks {
            let compressed_size = block
                .end
                .checked_sub(block.start)
                .ok_or(Error::DecompressionFailed(compression))?;
            stored_total = stored_total
                .checked_add(compressed_size)
                .ok_or(Error::DecompressionFailed(compression))?;
            let file_offset = if relative_offsets {
                self.offset
                    .checked_add(block.start)
                    .ok_or(Error::DecompressionFailed(compression))?
            } else {
                block.start
            };
            if file_offset < data_offset {
                return Err(Error::DecompressionFailed(compression));
            }

            let uncompressed_size = logical_remaining.min(logical_block_size);
            logical_remaining -= uncompressed_size;
            blocks.push(CompressedBlock {
                file_offset,
                compressed_size,
                uncompressed_size: usize::try_from(uncompressed_size)
                    .map_err(|_| Error::DecompressionFailed(compression))?,
            });
        }
        if logical_remaining != 0 || stored_total != self.compressed {
            return Err(Error::DecompressionFailed(compression));
        }
        Ok(blocks)
    }

    pub fn read_file<R: io::Read + io::Seek, W: io::Write>(
        &self,
        reader: &mut R,
        version: Version,
        compression: &[Option<Compression>],
        #[cfg_attr(not(feature = "oodle"), allow(unused_variables))] parallel_blocks: bool,
        #[allow(unused)] _key: &super::Key,
        buf: &mut W,
    ) -> Result<(), super::Error> {
        reader.seek(io::SeekFrom::Start(self.offset))?;
        Entry::read(reader, version)?;
        let data_offset = reader.stream_position()?;

        // This vendored build deliberately does not expose AES support. More
        // importantly, encrypted blocks cannot be streamed safely without the
        // missing key, so reject them before reading payload bytes.
        if self.is_encrypted() {
            return Err(super::Error::Encryption);
        }

        let compression_method = match self.compression_slot {
            None => None,
            Some(slot) => Some(
                compression
                    .get(slot as usize)
                    .copied()
                    .flatten()
                    .ok_or(super::Error::Compression)?,
            ),
        };

        let Some(comp) = compression_method else {
            if self.compressed != self.uncompressed {
                return Err(super::Error::Other(
                    "an uncompressed entry has different stored and logical sizes".to_owned(),
                ));
            }
            reader.seek(io::SeekFrom::Start(data_offset))?;
            let copied = io::copy(&mut io::Read::take(reader, self.compressed), buf)?;
            if copied != self.uncompressed {
                return Err(super::Error::Other(
                    "an uncompressed entry ended before its declared size".to_owned(),
                ));
            }
            buf.flush()?;
            return Ok(());
        };

        #[cfg(not(feature = "compression"))]
        return Err(super::Error::Compression);

        #[cfg(feature = "compression")]
        {
            let blocks = self.compressed_blocks(version, data_offset, comp)?;

            macro_rules! decode_streaming_blocks {
                ($decoder:expr) => {{
                    for block in &blocks {
                        reader.seek(io::SeekFrom::Start(block.file_offset))?;
                        let stored = io::Read::take(&mut *reader, block.compressed_size);
                        let mut decoder = $decoder(stored)?;
                        let mut output = ExactBlockWriter::new(buf, block.uncompressed_size);
                        io::copy(&mut decoder, &mut output)?;
                        output.finish(comp)?;
                    }
                }};
            }

            match comp {
                Compression::Zlib => decode_streaming_blocks!(|stored| {
                    Ok::<_, Error>(flate2::read::ZlibDecoder::new(stored))
                }),
                Compression::Gzip => decode_streaming_blocks!(|stored| {
                    Ok::<_, Error>(flate2::read::GzDecoder::new(stored))
                }),
                Compression::Zstd => decode_streaming_blocks!(|stored| {
                    Ok::<_, Error>(zstd::stream::read::Decoder::new(stored)?)
                }),
                Compression::LZ4 => {
                    for block in blocks {
                        let stored = read_block(reader, block, comp)?;
                        let mut output = allocation_buffer(block.uncompressed_size, comp)?;
                        let written = lz4_flex::block::decompress_into(&stored, &mut output)
                            .map_err(|_| Error::DecompressionFailed(comp))?;
                        if written != block.uncompressed_size {
                            return Err(Error::DecompressionFailed(comp));
                        }
                        buf.write_all(&output)?;
                    }
                }
                #[cfg(feature = "oodle")]
                Compression::Oodle => {
                    let oodle = oodle_loader::oodle()?;
                    let batch_width =
                        crate::parallel::worker_count(blocks.len(), parallel_blocks).max(1);
                    for block_batch in blocks.chunks(batch_width) {
                        let mut inputs = Vec::with_capacity(block_batch.len());
                        for &block in block_batch {
                            inputs
                                .push((read_block(reader, block, comp)?, block.uncompressed_size));
                        }
                        let outputs = crate::parallel::ordered_map(
                            &inputs,
                            parallel_blocks,
                            |_, (stored, uncompressed_size)| {
                                let mut output = allocation_buffer(*uncompressed_size, comp)?;
                                let written = oodle.decompress(stored, &mut output);
                                if written != *uncompressed_size as isize {
                                    return Err(Error::DecompressionFailed(comp));
                                }
                                Ok(output)
                            },
                        );
                        for output in outputs {
                            buf.write_all(&output?)?;
                        }
                    }
                }
                #[cfg(not(feature = "oodle"))]
                Compression::Oodle => return Err(super::Error::Oodle),
            }
        }
        buf.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

    const TEST_COMPRESSION_BLOCK_SIZE: usize = 0x3e << 11;

    struct TrackingReader {
        inner: Cursor<Vec<u8>>,
        total_read: u64,
        max_read_request: usize,
    }

    impl TrackingReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(data),
                total_read: 0,
                max_read_request: 0,
            }
        }

        fn reset_metrics(&mut self) {
            self.total_read = 0;
            self.max_read_request = 0;
        }
    }

    impl Read for TrackingReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.max_read_request = self.max_read_request.max(output.len());
            let read = self.inner.read(output)?;
            self.total_read += read as u64;
            Ok(read)
        }
    }

    impl Seek for TrackingReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[derive(Default)]
    struct TrackingWriter {
        data: Vec<u8>,
        max_write: usize,
    }

    impl Write for TrackingWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.max_write = self.max_write.max(data.len());
            self.data.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingWriter {
        remaining: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("operation cancelled"));
            }
            let accepted = self.remaining.min(data.len());
            self.remaining -= accepted;
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "compression")]
    fn deterministic_payload(block_count: usize) -> Vec<u8> {
        let mut state = 0x243f_6a88_u32;
        (0..(TEST_COMPRESSION_BLOCK_SIZE * block_count + 731))
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    #[cfg(feature = "compression")]
    fn compressed_pak(compression: super::Compression, payload: &[u8]) -> Vec<u8> {
        let output = Cursor::new(Vec::new());
        let mut writer = crate::PakBuilder::new().compression([compression]).writer(
            output,
            super::Version::V11,
            "../../../Example/Content/".to_owned(),
            Some(0x1234_5678),
        );
        writer.write_file("Data/Large.bin", true, payload).unwrap();
        writer.write_index().unwrap().into_inner()
    }

    #[cfg(feature = "compression")]
    fn assert_streamed_round_trip(compression: super::Compression, parallel_blocks: bool) {
        let payload = deterministic_payload(4);
        let pak = compressed_pak(compression, &payload);
        let pak_size = pak.len();
        let mut input = TrackingReader::new(pak);
        let reader = crate::PakBuilder::new()
            .parallel_blocks(parallel_blocks)
            .reader_with_version(&mut input, super::Version::V11)
            .unwrap();
        input.reset_metrics();

        let mut output = TrackingWriter::default();
        reader
            .read_file_with_parallel_blocks(
                "Data/Large.bin",
                &mut input,
                &mut output,
                parallel_blocks,
            )
            .unwrap();

        assert_eq!(output.data, payload);
        assert!(
            input.max_read_request <= TEST_COMPRESSION_BLOCK_SIZE * 2,
            "{compression:?} requested {} input bytes at once",
            input.max_read_request
        );
        assert!(
            output.max_write <= TEST_COMPRESSION_BLOCK_SIZE,
            "{compression:?} emitted {} output bytes at once",
            output.max_write
        );
        assert!(input.total_read < pak_size as u64);
    }

    #[test]
    fn test_entry() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xDD, 0x94, 0xFD, 0xC3, 0x5F, 0xF5, 0x91, 0xA9, 0x9A, 0x5E, 0x14, 0xDC, 0x9B,
            0xD3, 0x58, 0x89, 0x78, 0xA6, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = vec![];
        let entry = super::Entry::read(&mut std::io::Cursor::new(data.clone()), super::Version::V5)
            .unwrap();
        entry
            .write(&mut out, super::Version::V5, super::EntryLocation::Data)
            .unwrap();
        assert_eq!(&data, &out);
    }

    #[test]
    fn single_pass_uncompressed_output_matches_prehashed_output() {
        let data: Vec<_> = (0usize..(9 * 1024 * 1024 + 137))
            .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
            .collect();
        let prefix = b"prefix";

        let mut previous = Cursor::new(prefix.to_vec());
        previous.seek(SeekFrom::End(0)).unwrap();
        let offset = previous.stream_position().unwrap();
        let partial = crate::data::build_partial_entry(&[], false, data.as_slice()).unwrap();
        let expected_entry = partial
            .build_entry(super::Version::V11, &mut Vec::new(), offset)
            .unwrap();
        expected_entry
            .write(
                &mut previous,
                super::Version::V11,
                super::EntryLocation::Data,
            )
            .unwrap();
        partial.write_data(&mut previous).unwrap();

        let mut single_pass = Cursor::new(prefix.to_vec());
        single_pass.seek(SeekFrom::End(0)).unwrap();
        let mut progress = Vec::new();
        let mut report_progress = |completed, total| {
            progress.push((completed, total));
            true
        };
        let _actual_entry = super::Entry::write_uncompressed_file(
            &mut single_pass,
            super::Version::V11,
            &data,
            &mut report_progress,
            &mut |_| {},
        )
        .unwrap();

        assert_eq!(single_pass.into_inner(), previous.into_inner());
        assert_eq!(progress.first(), Some(&(0, data.len() as u64)));
        assert_eq!(
            progress.last(),
            Some(&(data.len() as u64, data.len() as u64))
        );
        assert!(progress.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    }

    #[test]
    fn uncompressed_output_honors_progress_cancellation() {
        let mut output = Cursor::new(Vec::new());
        let data = vec![0x5a; 8 * 1024 * 1024];
        let mut cancel_after_one_chunk = |completed, _| completed < 4 * 1024 * 1024;
        let error = super::Entry::write_uncompressed_file(
            &mut output,
            super::Version::V11,
            &data,
            &mut cancel_after_one_chunk,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn every_builtin_codec_decodes_in_bounded_blocks() {
        for compression in [
            super::Compression::Zlib,
            super::Compression::Gzip,
            super::Compression::Zstd,
            super::Compression::LZ4,
        ] {
            assert_streamed_round_trip(compression, true);
        }
    }

    #[cfg(all(feature = "compression", feature = "oodle"))]
    #[test]
    fn oodle_decodes_in_order_with_bounded_parallel_batches_when_enabled() {
        if std::env::var_os("PAK_MERGER_TEST_OODLE_OUTPUT").is_none() {
            return;
        }
        assert_streamed_round_trip(super::Compression::Oodle, false);
        assert_streamed_round_trip(super::Compression::Oodle, true);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn cancelled_stream_does_not_read_the_rest_of_a_large_entry() {
        let payload = deterministic_payload(12);
        let pak = compressed_pak(super::Compression::Zstd, &payload);
        let pak_size = pak.len() as u64;
        let mut input = TrackingReader::new(pak);
        let reader = crate::PakBuilder::new()
            .reader_with_version(&mut input, super::Version::V11)
            .unwrap();
        input.reset_metrics();

        let mut output = FailingWriter {
            remaining: TEST_COMPRESSION_BLOCK_SIZE + 4096,
        };
        let error = reader
            .read_file("Data/Large.bin", &mut input, &mut output)
            .unwrap_err();
        assert!(error.to_string().contains("operation cancelled"));
        assert!(
            input.total_read < pak_size / 2,
            "cancellation read {} of {pak_size} stored bytes",
            input.total_read
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn multi_gibibyte_entry_metadata_is_partitioned_without_a_logical_size_buffer() {
        let logical_size = u64::from(u32::MAX) + 10_000_000;
        let block_size = TEST_COMPRESSION_BLOCK_SIZE as u64;
        let block_count = logical_size.div_ceil(block_size) as usize;
        let header_size = 128_u64;
        let blocks = (0..block_count)
            .map(|index| super::Block {
                start: header_size + index as u64,
                end: header_size + index as u64 + 1,
            })
            .collect::<Vec<_>>();
        let entry = super::Entry {
            offset: 4096,
            compressed: block_count as u64,
            uncompressed: logical_size,
            compression_slot: Some(0),
            timestamp: None,
            hash: None,
            blocks: Some(blocks),
            flags: 0,
            compression_block_size: TEST_COMPRESSION_BLOCK_SIZE as u32,
        };

        let planned = entry
            .compressed_blocks(
                super::Version::V11,
                entry.offset + header_size,
                super::Compression::Zstd,
            )
            .unwrap();
        assert_eq!(planned.len(), block_count);
        assert_eq!(
            planned
                .iter()
                .map(|block| block.uncompressed_size as u64)
                .sum::<u64>(),
            logical_size
        );
        assert!(planned
            .iter()
            .all(|block| block.uncompressed_size <= TEST_COMPRESSION_BLOCK_SIZE));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn streamed_compressed_output_matches_prebuilt_output() {
        let size = crate::data::COMPRESSION_BLOCK_SIZE as usize * 11 + 137;
        let data: Vec<_> = (0..size)
            .map(|index| (index.wrapping_mul(29).wrapping_add(index >> 5) & 0xff) as u8)
            .collect();
        let prefix = b"compressed-prefix";

        let mut previous = Cursor::new(prefix.to_vec());
        previous.seek(SeekFrom::End(0)).unwrap();
        let offset = previous.stream_position().unwrap();
        let partial =
            crate::data::build_partial_entry(&[crate::Compression::Zstd], true, data.as_slice())
                .unwrap();
        let expected_entry = partial
            .build_entry(super::Version::V11, &mut Vec::new(), offset)
            .unwrap();
        expected_entry
            .write(
                &mut previous,
                super::Version::V11,
                super::EntryLocation::Data,
            )
            .unwrap();
        partial.write_data(&mut previous).unwrap();

        let mut streamed = Cursor::new(prefix.to_vec());
        streamed.seek(SeekFrom::End(0)).unwrap();
        let mut progress = Vec::new();
        let actual_entry = super::Entry::write_file(
            &mut streamed,
            super::Version::V11,
            &mut Vec::new(),
            &[crate::Compression::Zstd],
            true,
            &data,
            &mut |completed, total| {
                progress.push((completed, total));
                true
            },
        )
        .unwrap();

        assert_eq!(streamed.into_inner(), previous.into_inner());
        assert_eq!(actual_entry.compressed, expected_entry.compressed);
        assert_eq!(actual_entry.hash.unwrap().0, expected_entry.hash.unwrap().0);
        assert_eq!(progress.first(), Some(&(0, data.len() as u64)));
        assert_eq!(
            progress.last(),
            Some(&(data.len() as u64, data.len() as u64))
        );
        assert!(progress.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn streamed_compressed_output_honors_progress_cancellation() {
        let mut output = Cursor::new(Vec::new());
        let block_size = crate::data::COMPRESSION_BLOCK_SIZE as u64;
        let data = vec![0x5a; block_size as usize * 8];
        let error = super::Entry::write_file(
            &mut output,
            super::Version::V11,
            &mut Vec::new(),
            &[crate::Compression::Zstd],
            true,
            &data,
            &mut |completed, _| completed < block_size * 2,
        )
        .unwrap_err();

        assert!(error.to_string().contains("cancelled"));
        assert!(output.position() < data.len() as u64);
    }
}
