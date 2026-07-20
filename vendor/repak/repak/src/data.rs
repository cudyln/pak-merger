use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Condvar, Mutex},
};

use crate::{
    entry::{Block, Entry},
    Compression, Error, Hash, Version, VersionMajor,
};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Default compression block size used by Unreal Pak writers. Keeping this
/// value for ordinary entries preserves byte-identical output.
pub const COMPRESSION_BLOCK_SIZE: u32 = 0x3e << 11;
/// Pak v11 compact entries encode the compression-block count in 16 bits.
pub const MAX_COMPRESSION_BLOCKS: u32 = 0xffff;
const COMPRESSION_BLOCK_ALIGNMENT: u64 = 1 << 11;

/// Compression layout selected for one output entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionBlockLayout {
    pub block_size: u32,
    pub block_count: u32,
}

/// Selects the smallest deterministic block size that keeps the v11 encoded
/// block count representable. Entries that already fit use Unreal's usual
/// 126,976-byte blocks; larger entries increase the size in 2 KiB steps.
///
/// This helper only performs checked integer arithmetic and does not inspect
/// or allocate the entry payload, so callers can also use it for disk-space
/// preflight.
pub fn compression_block_layout(uncompressed_size: u64) -> Result<CompressionBlockLayout> {
    if uncompressed_size == 0 {
        return Ok(CompressionBlockLayout {
            block_size: COMPRESSION_BLOCK_SIZE,
            block_count: 0,
        });
    }

    let minimum_block_size = uncompressed_size.div_ceil(u64::from(MAX_COMPRESSION_BLOCKS));
    let requested = minimum_block_size.max(u64::from(COMPRESSION_BLOCK_SIZE));
    let aligned = requested
        .checked_add(COMPRESSION_BLOCK_ALIGNMENT - 1)
        .map(|value| value / COMPRESSION_BLOCK_ALIGNMENT * COMPRESSION_BLOCK_ALIGNMENT);
    // Near u32::MAX there is no larger 2 KiB-aligned representable value. Use
    // the exact required size in that narrow range rather than rejecting an
    // otherwise representable layout.
    let block_size = match aligned {
        Some(value) if value <= u64::from(u32::MAX) => value,
        _ if requested <= u64::from(u32::MAX) => requested,
        _ => {
            return Err(Error::Other(format!(
                "compressed entry of {uncompressed_size} bytes needs a block larger than u32"
            )));
        }
    };
    let block_size_u32 = u32::try_from(block_size)
        .map_err(|_| Error::Other("compression block size does not fit u32".to_owned()))?;
    let _block_size_usize = usize::try_from(block_size_u32)
        .map_err(|_| Error::Other("compression block size does not fit usize".to_owned()))?;
    let block_count = uncompressed_size.div_ceil(block_size);
    if block_count > u64::from(MAX_COMPRESSION_BLOCKS) {
        return Err(Error::Other(format!(
            "compressed entry needs {block_count} blocks, above the Pak v11 limit of {MAX_COMPRESSION_BLOCKS}"
        )));
    }
    let block_count = u32::try_from(block_count)
        .map_err(|_| Error::Other("compression block count does not fit u32".to_owned()))?;

    Ok(CompressionBlockLayout {
        block_size: block_size_u32,
        block_count,
    })
}

struct OrderedWorkState {
    next_to_schedule: usize,
    consumed: usize,
    allowed_exclusive: usize,
    peak_in_flight: usize,
    stop: bool,
}

#[derive(Debug, Clone, Copy)]
struct OrderedWorkStats {
    peak_in_flight: usize,
    window: usize,
}

/// Runs independent operations concurrently while handing values to `consume`
/// in index order. At most two blocks per worker are scheduled ahead of the
/// last consumed block, so an unusually slow early block cannot make every
/// later compressed block accumulate in memory.
fn ordered_bounded_try_for_each<U, F, C>(
    item_count: usize,
    parallel: bool,
    operation: F,
    mut consume: C,
) -> Result<OrderedWorkStats>
where
    U: Send,
    F: Fn(usize) -> Result<U> + Sync,
    C: FnMut(usize, U) -> Result<()>,
{
    if item_count == 0 {
        return Ok(OrderedWorkStats {
            peak_in_flight: 0,
            window: 0,
        });
    }

    let worker_count = crate::parallel::worker_count(item_count, parallel);
    let window = worker_count.saturating_mul(2).clamp(1, item_count);
    let state = (
        Mutex::new(OrderedWorkState {
            next_to_schedule: 0,
            consumed: 0,
            allowed_exclusive: window,
            peak_in_flight: 0,
            stop: false,
        }),
        Condvar::new(),
    );
    let (sender, receiver) = std::sync::mpsc::channel::<(usize, Result<U>)>();

    std::thread::scope(|scope| -> Result<OrderedWorkStats> {
        let (state_lock, state_changed) = (&state.0, &state.1);
        for _ in 0..worker_count {
            let sender = sender.clone();
            let operation = &operation;
            scope.spawn(move || loop {
                let index = {
                    let mut state = match state_lock.lock() {
                        Ok(state) => state,
                        Err(_) => break,
                    };
                    while !state.stop
                        && state.next_to_schedule < item_count
                        && state.next_to_schedule >= state.allowed_exclusive
                    {
                        state = match state_changed.wait(state) {
                            Ok(state) => state,
                            Err(_) => return,
                        };
                    }
                    if state.stop || state.next_to_schedule >= item_count {
                        break;
                    }
                    let index = state.next_to_schedule;
                    state.next_to_schedule += 1;
                    let in_flight = state.next_to_schedule.saturating_sub(state.consumed);
                    state.peak_in_flight = state.peak_in_flight.max(in_flight);
                    index
                };

                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(index)))
                        .unwrap_or_else(|_| {
                            Err(Error::Other(
                                "parallel compression worker panicked".to_owned(),
                            ))
                        });
                if sender.send((index, result)).is_err() {
                    break;
                }
            });
        }
        drop(sender);

        let mut pending = BTreeMap::new();
        let mut next_to_consume = 0_usize;
        let mut failure = None;
        while next_to_consume < item_count {
            let (index, result) = match receiver.recv() {
                Ok(result) => result,
                Err(_) => {
                    failure = Some(Error::Other(
                        "parallel compression workers ended before every block was returned"
                            .to_owned(),
                    ));
                    break;
                }
            };
            pending.insert(index, result);

            while let Some(result) = pending.remove(&next_to_consume) {
                let result = result.and_then(|value| {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        consume(next_to_consume, value)
                    }))
                    .unwrap_or_else(|_| {
                        Err(Error::Other(
                            "ordered compression consumer panicked".to_owned(),
                        ))
                    })
                });
                match result {
                    Ok(()) => {}
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
                next_to_consume += 1;
                let mut state = state_lock
                    .lock()
                    .map_err(|_| Error::Other("compression scheduler was poisoned".to_owned()))?;
                state.consumed = next_to_consume;
                state.allowed_exclusive = next_to_consume.saturating_add(window).min(item_count);
                state_changed.notify_all();
            }
            if failure.is_some() {
                break;
            }
        }

        let stats = {
            let mut state = state_lock
                .lock()
                .map_err(|_| Error::Other("compression scheduler was poisoned".to_owned()))?;
            state.stop = true;
            let stats = OrderedWorkStats {
                peak_in_flight: state.peak_in_flight,
                window,
            };
            state_changed.notify_all();
            stats
        };

        if let Some(error) = failure {
            Err(error)
        } else {
            debug_assert!(stats.peak_in_flight <= stats.window);
            Ok(stats)
        }
    })
}

pub(crate) struct StreamedCompression {
    pub(crate) compressed_size: u64,
    pub(crate) hash: Hash,
    pub(crate) block_sizes: Vec<u64>,
    #[cfg(test)]
    peak_in_flight_blocks: usize,
    #[cfg(test)]
    in_flight_window: usize,
}

/// Compresses every source block exactly once and writes completed blocks to
/// the final Pak stream in source order. Only a bounded scheduling window is
/// retained on the heap; the full entry is never assembled as a `Vec<Vec<u8>>`.
#[cfg(feature = "compression")]
pub(crate) fn write_compressed_blocks_with_progress<W, P, S>(
    writer: &mut W,
    compression: Compression,
    parallel_blocks: bool,
    compression_block_size: u32,
    data: &[u8],
    progress: &mut P,
    source_chunks: &mut S,
) -> Result<StreamedCompression>
where
    W: Write,
    P: FnMut(u64) -> bool,
    S: FnMut(&[u8]),
{
    use sha1::{Digest, Sha1};

    let block_size = usize::try_from(compression_block_size)
        .map_err(|_| Error::Other("compression block size does not fit usize".to_owned()))?;
    if block_size == 0 {
        return Err(Error::Other(
            "compression block size must not be zero".to_owned(),
        ));
    }
    let block_count = data.len().div_ceil(block_size);
    if block_count > MAX_COMPRESSION_BLOCKS as usize {
        return Err(Error::Other(format!(
            "compressed entry needs {block_count} blocks, above the Pak v11 limit of {MAX_COMPRESSION_BLOCKS}"
        )));
    }
    let mut hasher = Sha1::new();
    let mut compressed_size = 0_u64;
    let mut source_offset = 0_usize;
    let mut block_sizes = Vec::with_capacity(block_count);
    let stats = ordered_bounded_try_for_each(
        block_count,
        parallel_blocks,
        |index| {
            let start = index
                .checked_mul(block_size)
                .ok_or_else(|| Error::Other("compression block offset overflowed".to_owned()))?;
            let remaining = data
                .len()
                .checked_sub(start)
                .ok_or_else(|| Error::Other("compression block offset exceeds input".to_owned()))?;
            let end = start
                .checked_add(remaining.min(block_size))
                .ok_or_else(|| Error::Other("compression block end overflowed".to_owned()))?;
            let source = &data[start..end];
            Ok(PartialBlock {
                uncompressed_size: source.len(),
                data: compress(compression, source)?,
            })
        },
        |_, block| {
            writer.write_all(&block.data)?;
            compressed_size = compressed_size.saturating_add(block.data.len() as u64);
            hasher.update(&block.data);
            block_sizes.push(block.data.len() as u64);
            let source_end = source_offset
                .checked_add(block.uncompressed_size)
                .filter(|&end| end <= data.len())
                .ok_or_else(|| Error::Other("source callback range overflowed".to_owned()))?;
            source_chunks(&data[source_offset..source_end]);
            source_offset = source_end;
            if !progress(block.uncompressed_size as u64) {
                return Err(Error::Other("operation cancelled".to_owned()));
            }
            Ok(())
        },
    )?;
    #[cfg(not(test))]
    let _ = stats;
    debug_assert_eq!(source_offset, data.len());

    Ok(StreamedCompression {
        compressed_size,
        hash: Hash(hasher.finalize().into()),
        block_sizes,
        #[cfg(test)]
        peak_in_flight_blocks: stats.peak_in_flight,
        #[cfg(test)]
        in_flight_window: stats.window,
    })
}

pub struct PartialEntry<D: AsRef<[u8]>> {
    compression: Option<Compression>,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_block_size: u32,
    data: PartialEntryData<D>,
    hash: Hash,
}
pub(crate) struct PartialBlock {
    uncompressed_size: usize,
    data: Vec<u8>,
}
pub(crate) enum PartialEntryData<D> {
    Slice(D),
    Blocks(Vec<PartialBlock>),
}

#[cfg(feature = "compression")]
pub(crate) fn get_compression_slot(
    version: Version,
    compression_slots: &mut Vec<Option<Compression>>,
    compression: Compression,
) -> Result<u32> {
    let slot = compression_slots
        .iter()
        .enumerate()
        .find(|(_, s)| **s == Some(compression));
    Ok(if let Some((i, _)) = slot {
        // existing found
        i
    } else {
        if version.version_major() < VersionMajor::FNameBasedCompression {
            return Err(Error::Other(format!(
                "cannot use {compression:?} prior to FNameBasedCompression (pak version 8)"
            )));
        }

        // find empty slot
        if let Some((i, empty_slot)) = compression_slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.is_none())
        {
            // empty found, set it to used compression type
            *empty_slot = Some(compression);
            i
        } else {
            // no empty slot found, add a new one
            compression_slots.push(Some(compression));
            compression_slots.len() - 1
        }
    } as u32)
}

impl<D: AsRef<[u8]>> PartialEntry<D> {
    pub(crate) fn build_entry(
        &self,
        version: Version,
        #[allow(unused)] compression_slots: &mut Vec<Option<Compression>>,
        file_offset: u64,
    ) -> Result<Entry> {
        #[cfg(feature = "compression")]
        let compression_slot = {
            let empty = match &self.data {
                PartialEntryData::Slice(s) => s.as_ref().is_empty(),
                PartialEntryData::Blocks(blocks) => blocks.is_empty(),
            };
            if empty {
                None
            } else {
                self.compression
                    .map(|c| get_compression_slot(version, compression_slots, c))
                    .transpose()?
            }
        };
        #[cfg(not(feature = "compression"))]
        let compression_slot = None;

        let blocks = match &self.data {
            PartialEntryData::Slice(_) => None,
            PartialEntryData::Blocks(blocks) => {
                let entry_size =
                    Entry::get_serialized_size(version, compression_slot, blocks.len() as u32);

                let mut offset = entry_size;
                if version.version_major() < VersionMajor::RelativeChunkOffsets {
                    offset += file_offset;
                };

                Some(
                    blocks
                        .iter()
                        .map(|block| {
                            let start = offset;
                            offset += block.data.len() as u64;
                            let end = offset;
                            Block { start, end }
                        })
                        .collect(),
                )
            }
        };

        Ok(Entry {
            offset: file_offset,
            compressed: self.compressed_size,
            uncompressed: self.uncompressed_size,
            compression_slot,
            timestamp: None,
            hash: Some(self.hash),
            blocks,
            flags: 0,
            compression_block_size: self.compression_block_size,
        })
    }
    pub(crate) fn write_data<S: Write>(&self, stream: &mut S) -> Result<()> {
        match &self.data {
            PartialEntryData::Slice(data) => {
                stream.write_all(data.as_ref())?;
            }
            PartialEntryData::Blocks(blocks) => {
                for block in blocks {
                    stream.write_all(&block.data)?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn build_partial_entry<D>(
    allowed_compression: &[Compression],
    parallel_blocks: bool,
    data: D,
) -> Result<PartialEntry<D>>
where
    D: AsRef<[u8]>,
{
    let mut progress = |_| true;
    build_partial_entry_with_progress(allowed_compression, parallel_blocks, data, &mut progress)
}

pub(crate) fn build_partial_entry_with_progress<D, P>(
    allowed_compression: &[Compression],
    parallel_blocks: bool,
    data: D,
    progress: &mut P,
) -> Result<PartialEntry<D>>
where
    D: AsRef<[u8]>,
    P: FnMut(u64) -> bool,
{
    // TODO hash needs to be post-compression/encryption
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();

    // TODO possibly select best compression based on some criteria instead of picking first
    let compression = allowed_compression.first().cloned();
    let uncompressed_size = data.as_ref().len() as u64;
    let compression_block_size;

    let (data, compressed_size) = match compression {
        #[cfg(not(feature = "compression"))]
        Some(_) => {
            unreachable!("should not be able to reach this point without compression feature")
        }
        #[cfg(feature = "compression")]
        Some(compression) => {
            // https://github.com/EpicGames/UnrealEngine/commit/3aad0ff7976be1073005dca2c1282af548b45d89
            // Block size must fit into flags field or it may cause unreadable paks for earlier Unreal Engine versions
            let layout = compression_block_layout(uncompressed_size)?;
            compression_block_size = layout.block_size;
            let block_size = usize::try_from(layout.block_size).map_err(|_| {
                Error::Other("compression block size does not fit usize".to_owned())
            })?;
            let source_bytes = data.as_ref();
            let block_count = usize::try_from(layout.block_count).map_err(|_| {
                Error::Other("compression block count does not fit usize".to_owned())
            })?;
            let mut compressed_size = 0_u64;
            let mut blocks = Vec::with_capacity(block_count);
            let _stats = ordered_bounded_try_for_each(
                block_count,
                parallel_blocks,
                |index| {
                    let start = index.checked_mul(block_size).ok_or_else(|| {
                        Error::Other("compression block offset overflowed".to_owned())
                    })?;
                    let remaining = source_bytes.len().checked_sub(start).ok_or_else(|| {
                        Error::Other("compression block offset exceeds input".to_owned())
                    })?;
                    let end = start
                        .checked_add(remaining.min(block_size))
                        .ok_or_else(|| {
                            Error::Other("compression block end overflowed".to_owned())
                        })?;
                    let source = &source_bytes[start..end];
                    Ok(PartialBlock {
                        uncompressed_size: source.len(),
                        data: compress(compression, source)?,
                    })
                },
                |_, block| {
                    compressed_size = compressed_size.saturating_add(block.data.len() as u64);
                    hasher.update(&block.data);
                    if !progress(block.uncompressed_size as u64) {
                        return Err(Error::Other("operation cancelled".to_owned()));
                    }
                    blocks.push(block);
                    Ok(())
                },
            )?;

            (PartialEntryData::Blocks(blocks), compressed_size)
        }
        None => {
            compression_block_size = 0;
            hasher.update(data.as_ref());
            (PartialEntryData::Slice(data), uncompressed_size)
        }
    };

    Ok(PartialEntry {
        compression,
        compressed_size,
        uncompressed_size,
        compression_block_size,
        data,
        hash: Hash(hasher.finalize().into()),
    })
}

#[cfg(feature = "compression")]
fn compress(compression: Compression, data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let compressed = match compression {
        Compression::Zlib => {
            let mut compress =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Gzip => {
            let mut compress =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Zstd => zstd::stream::encode_all(data, 0)?,
        Compression::LZ4 => lz4_flex::block::compress(data),
        Compression::Oodle => {
            #[cfg(not(feature = "oodle"))]
            return Err(super::Error::Oodle);
            #[cfg(feature = "oodle")]
            {
                oodle_loader::oodle()?.compress(
                    data.as_ref(),
                    oodle_loader::Compressor::Mermaid,
                    oodle_loader::CompressionLevel::SuperFast,
                )?
            }
        }
    };

    Ok(compressed)
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use super::{
        compression_block_layout, ordered_bounded_try_for_each,
        write_compressed_blocks_with_progress, COMPRESSION_BLOCK_SIZE, MAX_COMPRESSION_BLOCKS,
    };
    use crate::{Compression, Error};

    #[test]
    fn bounded_scheduler_consumes_in_order_and_runs_each_item_once() {
        let item_count = 97;
        let calls: Arc<Vec<_>> = Arc::new((0..item_count).map(|_| AtomicUsize::new(0)).collect());
        let operation_calls = Arc::clone(&calls);
        let mut consumed = Vec::new();
        let stats = ordered_bounded_try_for_each(
            item_count,
            true,
            move |index| {
                operation_calls[index].fetch_add(1, Ordering::Relaxed);
                if index == 0 {
                    std::thread::sleep(Duration::from_millis(10));
                } else if index % 3 == 0 {
                    std::thread::yield_now();
                }
                Ok(index)
            },
            |index, value| {
                assert_eq!(index, value);
                consumed.push(value);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(consumed, (0..item_count).collect::<Vec<_>>());
        assert!(calls.iter().all(|calls| calls.load(Ordering::Relaxed) == 1));
        assert!(stats.peak_in_flight <= stats.window);
        assert!(stats.window <= crate::parallel::worker_count(item_count, true) * 2);
    }

    #[test]
    fn bounded_scheduler_cancellation_stops_ordered_consumption() {
        let mut consumed = Vec::new();
        let error = ordered_bounded_try_for_each(128, true, Ok, |index, value| {
            if index == 5 {
                return Err(Error::Other("operation cancelled".to_owned()));
            }
            consumed.push(value);
            Ok(())
        })
        .unwrap_err();

        assert!(error.to_string().contains("cancelled"));
        assert_eq!(consumed, (0..5).collect::<Vec<_>>());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn streamed_compression_is_bounded_ordered_and_deterministic() {
        let size = COMPRESSION_BLOCK_SIZE as usize * 19 + 73;
        let data: Vec<_> = (0..size)
            .map(|index| (index.wrapping_mul(131).wrapping_add(index >> 3) & 0xff) as u8)
            .collect();

        let run = || {
            let mut output = Cursor::new(Vec::new());
            let mut completed = 0_u64;
            let metadata = write_compressed_blocks_with_progress(
                &mut output,
                Compression::Zstd,
                true,
                COMPRESSION_BLOCK_SIZE,
                &data,
                &mut |delta| {
                    completed += delta;
                    true
                },
                &mut |_| {},
            )
            .unwrap();
            (output.into_inner(), metadata, completed)
        };

        let (first_bytes, first, first_completed) = run();
        let (second_bytes, second, second_completed) = run();
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first.block_sizes, second.block_sizes);
        assert_eq!(first.hash.0, second.hash.0);
        assert_eq!(first.compressed_size, first_bytes.len() as u64);
        assert_eq!(first_completed, data.len() as u64);
        assert_eq!(second_completed, data.len() as u64);
        assert!(first.peak_in_flight_blocks <= first.in_flight_window);
        assert_eq!(first.block_sizes.len(), 20);
    }

    #[test]
    fn compression_layout_preserves_small_outputs_and_scales_for_twenty_gib() {
        let unchanged_limit = u64::from(COMPRESSION_BLOCK_SIZE) * u64::from(MAX_COMPRESSION_BLOCKS);
        let unchanged = compression_block_layout(unchanged_limit).unwrap();
        assert_eq!(unchanged.block_size, COMPRESSION_BLOCK_SIZE);
        assert_eq!(unchanged.block_count, MAX_COMPRESSION_BLOCKS);

        let twenty_gib = 20_u64 * 1024 * 1024 * 1024;
        let scaled = compression_block_layout(twenty_gib).unwrap();
        assert!(scaled.block_size > COMPRESSION_BLOCK_SIZE);
        assert_eq!(scaled.block_size % 2048, 0);
        assert!(scaled.block_count <= MAX_COMPRESSION_BLOCKS);
        assert_eq!(
            scaled.block_count,
            twenty_gib.div_ceil(u64::from(scaled.block_size)) as u32
        );
    }

    #[test]
    fn compression_layout_handles_boundaries_and_rejects_unrepresentable_sizes() {
        let first_scaled = u64::from(COMPRESSION_BLOCK_SIZE)
            .checked_mul(u64::from(MAX_COMPRESSION_BLOCKS))
            .unwrap()
            + 1;
        let scaled = compression_block_layout(first_scaled).unwrap();
        assert_eq!(scaled.block_size, COMPRESSION_BLOCK_SIZE + 2048);
        assert!(scaled.block_count <= MAX_COMPRESSION_BLOCKS);

        let largest_representable = u64::from(u32::MAX) * u64::from(MAX_COMPRESSION_BLOCKS);
        let boundary = compression_block_layout(largest_representable).unwrap();
        assert_eq!(boundary.block_size, u32::MAX);
        assert_eq!(boundary.block_count, MAX_COMPRESSION_BLOCKS);

        let error = compression_block_layout(largest_representable + 1).unwrap_err();
        assert!(error.to_string().contains("larger than u32"));
        assert!(compression_block_layout(u64::MAX).is_err());
    }
}
