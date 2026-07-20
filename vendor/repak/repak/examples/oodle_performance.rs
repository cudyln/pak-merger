use std::{
    io::{Cursor, Write},
    time::{Duration, Instant},
};

use repak::{Compression, PakBuilder, Version};
use sha1::{Digest, Sha1};

const MIB: usize = 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let size_mib = std::env::args()
        .nth(1)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(128usize);
    let source = synthetic_payload(size_mib * MIB);
    println!(
        "synthetic input: {size_mib} MiB, logical CPUs: {}",
        std::thread::available_parallelism().map_or(1, usize::from)
    );

    let (normal_block_bytes, normal_block_time) = upstream_normal_blocks(&source)?;
    let (old_plain_size, old_plain_time) = old_uncompressed_two_pass(&source)?;
    let (new_plain_size, new_plain_time) = write_uncompressed(&source)?;
    let (single_pak, single_time) = write_oodle(&source, false)?;
    let (parallel_pak, parallel_time) = write_oodle(&source, true)?;
    assert_eq!(parallel_pak, single_pak, "thread count changed Pak bytes");

    let (single_decoded, single_decode_time) = read_oodle(&single_pak, false)?;
    let (parallel_decoded, parallel_decode_time) = read_oodle(&parallel_pak, true)?;
    assert_eq!(single_decoded, source);
    assert_eq!(parallel_decoded, source);

    println!(
        "old uncompressed prehash + copy: {:?} ({:.1} MiB/s, {} bytes)",
        old_plain_time,
        throughput(size_mib, old_plain_time),
        old_plain_size
    );
    println!(
        "single-pass uncompressed Pak: {:?} ({:.1} MiB/s, {} bytes, {:.2}x)",
        new_plain_time,
        throughput(size_mib, new_plain_time),
        new_plain_size,
        speedup(old_plain_time, new_plain_time)
    );
    println!(
        "upstream Mermaid Normal block loop: {:?} ({:.1} MiB/s, {} bytes)",
        normal_block_time,
        throughput(size_mib, normal_block_time),
        normal_block_bytes
    );
    println!(
        "encode 1 thread: {:?} ({:.1} MiB/s)",
        single_time,
        throughput(size_mib, single_time)
    );
    println!(
        "encode all CPUs: {:?} ({:.1} MiB/s, {:.2}x)",
        parallel_time,
        throughput(size_mib, parallel_time),
        speedup(single_time, parallel_time)
    );
    println!(
        "decode 1 thread: {:?} ({:.1} MiB/s)",
        single_decode_time,
        throughput(size_mib, single_decode_time)
    );
    println!(
        "decode all CPUs: {:?} ({:.1} MiB/s, {:.2}x)",
        parallel_decode_time,
        throughput(size_mib, parallel_decode_time),
        speedup(single_decode_time, parallel_decode_time)
    );
    println!(
        "output: {:.2} MiB ({:.1}% of input); ordered output is byte-identical",
        parallel_pak.len() as f64 / MIB as f64,
        parallel_pak.len() as f64 * 100.0 / source.len() as f64
    );
    Ok(())
}

fn old_uncompressed_two_pass(source: &[u8]) -> Result<(usize, Duration), std::io::Error> {
    let start = Instant::now();
    let mut hasher = Sha1::new();
    hasher.update(source);
    std::hint::black_box(hasher.finalize());
    let mut output = Vec::with_capacity(source.len());
    output.write_all(source)?;
    std::hint::black_box(output.as_ptr());
    Ok((output.len(), start.elapsed()))
}

fn write_uncompressed(source: &[u8]) -> Result<(usize, Duration), repak::Error> {
    let mut writer = PakBuilder::new().writer(
        Cursor::new(Vec::with_capacity(source.len() + 1024)),
        Version::V11,
        "../../../Synthetic/Content/".to_owned(),
        Some(0),
    );
    let start = Instant::now();
    writer.write_file("Data/Database.uasset", false, source)?;
    let output = writer.write_index()?.into_inner();
    std::hint::black_box(output.as_ptr());
    Ok((output.len(), start.elapsed()))
}

fn upstream_normal_blocks(source: &[u8]) -> Result<(usize, Duration), oodle_loader::Error> {
    const BLOCK_SIZE: usize = 0x3e << 11;
    let start = Instant::now();
    let mut output_size = 0;
    for block in source.chunks(BLOCK_SIZE) {
        output_size += oodle_loader::oodle()?
            .compress(
                block,
                oodle_loader::Compressor::Mermaid,
                oodle_loader::CompressionLevel::Normal,
            )?
            .len();
    }
    Ok((output_size, start.elapsed()))
}

fn write_oodle(source: &[u8], parallel: bool) -> Result<(Vec<u8>, Duration), repak::Error> {
    let mut writer = PakBuilder::new()
        .compression([Compression::Oodle])
        .parallel_blocks(parallel)
        .writer(
            Cursor::new(Vec::new()),
            Version::V11,
            "../../../Synthetic/Content/".to_owned(),
            Some(0),
        );
    let start = Instant::now();
    writer.write_file("Data/Database.uasset", true, source)?;
    let output = writer.write_index()?.into_inner();
    Ok((output, start.elapsed()))
}

fn read_oodle(pak: &[u8], parallel: bool) -> Result<(Vec<u8>, Duration), repak::Error> {
    let mut source = Cursor::new(pak);
    let reader = PakBuilder::new()
        .parallel_blocks(parallel)
        .reader_with_version(&mut source, Version::V11)?;
    let start = Instant::now();
    let output = reader.get("Data/Database.uasset", &mut source)?;
    Ok((output, start.elapsed()))
}

fn synthetic_payload(size: usize) -> Vec<u8> {
    const PATTERN: &[u8] = b"m_DataList:m_id:m_Name:m_Params:OctopathTraveler0:";
    let mut output = vec![0; size];
    for (index, chunk) in output.chunks_mut(4096).enumerate() {
        for (offset, byte) in chunk.iter_mut().enumerate() {
            *byte = PATTERN[(index * 17 + offset) % PATTERN.len()];
        }
        let marker = (index as u64).to_le_bytes();
        let marker_len = marker.len().min(chunk.len());
        chunk[..marker_len].copy_from_slice(&marker[..marker_len]);
    }
    output
}

fn throughput(size_mib: usize, elapsed: Duration) -> f64 {
    size_mib as f64 / elapsed.as_secs_f64()
}

fn speedup(single: Duration, parallel: Duration) -> f64 {
    single.as_secs_f64() / parallel.as_secs_f64()
}
