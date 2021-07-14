use crate::vhdx_header::RegionTableEntry;
use crate::vhdx_metadata::DiskSpec;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use remain::sorted;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::mem::size_of;

// Payload BAT Entry States
pub const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
pub const PAYLOAD_BLOCK_UNDEFINED: u64 = 1;
pub const PAYLOAD_BLOCK_ZERO: u64 = 2;
pub const PAYLOAD_BLOCK_UNMAPPED: u64 = 3;
pub const PAYLOAD_BLOCK_UNMAPPED_v095: u64 = 5;
pub const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
pub const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;

pub const SB_BLOCK_NOT_PRESENT: u64 = 0;
pub const SB_BLOCK_PRESENT: u64 = 6;

// mask for the BAT state
pub const BAT_STATE_BIT_MASK: u64 = 0x07;
// mask for the offset within the file in units of 1 MB
pub const BAT_FILE_OFF_MASK: u64 = 0xFFFFFFFFFFF00000;

macro_rules! div_round_up {
    ($n:expr,$d:expr) => {{
        ($n + $d - 1) / $d
    }};
}

#[sorted]
pub enum Error {
    // Invalid BAT entry
    InvalidBatEntry,
    // Invalid number of BAT entries
    InvalidEntryCount,
    // Failed to read BAT from file
    ReadBat(io::Error),
    // Failed to write BAT entries to file
    WriteBat(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            InvalidBatEntry => write!(f, "Invalid BAT entry"),
            InvalidEntryCount => write!(f, "Invalid BAT entry count"),
            ReadBat(e) => write!(f, "Failed to read BAT entry {}", e),
            WriteBat(e) => write!(f, "Failed to read BAT entry {}", e),
        }
    }
}

pub struct BatEntry {
    bat_entry: u64,
}

impl BatEntry {
    pub fn collect_bat_entries(
        f: &mut File,
        disk_spec: DiskSpec,
        bat_entry: RegionTableEntry,
    ) -> Result<Vec<u64>> {
        let entry_count = BatEntry::calculate_entries(
            disk_spec.block_size,
            disk_spec.virtual_disk_size,
            disk_spec.chunk_ratio,
        );
        if entry_count as usize > (bat_entry.length as usize / size_of::<BatEntry>()) {
            return Err(Error::InvalidEntryCount);
        }

        let mut bat_entries: Vec<u64> = vec![0; bat_entry.length as usize];
        let offset = bat_entry.file_offset;
        for i in 0..entry_count {
            f.seek(SeekFrom::Start(offset + i * size_of::<u64>() as u64))
                .map_err(Error::ReadBat)?;

            let entry = f.read_u64::<LittleEndian>().map_err(Error::ReadBat)?;
            bat_entries.insert(i as usize, entry);
        }

        Ok(bat_entries)
    }

    fn calculate_entries(block_size: u32, virtual_disk_size: u64, chunk_ratio: u64) -> u64 {
        let data_blocks_count = div_round_up!(virtual_disk_size, block_size as u64);
        return data_blocks_count + (data_blocks_count - 1) / chunk_ratio;
    }

    pub fn write_bat_entries(f: &mut File, bat_offset: u64, bat_entries: Vec<u64>) -> Result<()> {
        let entry_count = bat_entries.len() as u64;
        let offset = bat_offset;
        for i in 0..entry_count {
            f.seek(SeekFrom::Start(offset + i * size_of::<u64>() as u64))
                .map_err(Error::ReadBat)?;
            let entry = match bat_entries.get(i as usize) {
                Some(entry) => entry,
                None => {
                    return Err(Error::InvalidBatEntry);
                }
            };

            f.write_u64::<LittleEndian>(*entry)
                .map_err(Error::ReadBat)?;
        }
        Ok(())
    }
}
