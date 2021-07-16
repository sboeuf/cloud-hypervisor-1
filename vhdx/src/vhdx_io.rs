use crate::vhdx_bat::{self, BatEntry};
use crate::vhdx_metadata::{self, DiskSpec};
use remain::sorted;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;

const SECTOR_SIZE: u64 = 512;

#[sorted]
pub enum Error {
    // Invalid BAT entry state
    InvalidBatEntryState,
    // Invalid number of BAT entries
    InvalidBatIndex,
    // Resulting too big disk size
    InvalidDiskSize,
    // Failed reading a sector block
    ReadSectorBlock(io::Error),
    // Failed resizing the VHDx file
    ResizeFile(io::Error),
    // Differencing mode is not supported
    UnsupportedMode,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            InvalidBatEntryState => write!(f, "Invalid BAT entry state"),
            InvalidBatIndex => write!(f, "Invalid BAT entry count"),
            InvalidDiskSize => write!(f, "Invalid disk size"),
            ReadSectorBlock(e) => write!(f, "Failed reading sector blocks form file {}", e),
            ResizeFile(e) => write!(f, "Failed changing file length {}", e),
            UnsupportedMode => write!(f, "Differencing mode is not supported yet"),
        }
    }
}

macro_rules! round_up {
    ($n:expr, $align:expr) => {{
        if $align > $n {
            $align
        } else {
            let rem = $n % $align;
            (($n / $align) + rem) * $align
        }
    }};
}

#[derive(Default)]
struct Sector {
    bat_index: u64,
    free_sectors: u64,
    free_bytes: u64,
    file_offset: u64,
    block_offset: u64,
}

impl Sector {
    pub fn new(
        disk_spec: &DiskSpec,
        bat: &Vec<u64>,
        sector_index: &u64,
        sector_count: &u64,
    ) -> Result<Sector> {
        let mut sector = Sector::default();

        sector.bat_index = *sector_index / disk_spec.sectors_per_block as u64;
        sector.block_offset = *sector_index % disk_spec.sectors_per_block as u64;
        sector.free_sectors = disk_spec.sectors_per_block as u64 - sector.block_offset;
        if sector.free_sectors > *sector_count {
            sector.free_sectors = *sector_count;
        }

        sector.free_bytes = sector.free_sectors * disk_spec.logical_sector_size as u64;
        sector.block_offset = sector.block_offset * disk_spec.logical_sector_size as u64;

        let bat_entry = match bat.get(sector.bat_index as usize) {
            Some(bat_entry) => bat_entry,
            None => {
                return Err(Error::InvalidBatIndex);
            }
        };
        sector.file_offset = *bat_entry & vhdx_bat::BAT_FILE_OFF_MASK;
        if sector.file_offset != 0 {
            sector.file_offset += sector.block_offset;
        }

        Ok(sector)
    }
}

pub fn read(
    f: &mut File,
    buf: &mut [u8],
    disk_spec: &DiskSpec,
    bat_entries: &Vec<u64>,
    mut sector_index: u64,
    mut sector_count: u64,
) -> Result<usize> {
    let mut read_count: usize = 0;

    while sector_count > 0 {
        if disk_spec.has_parent {
            return Err(Error::UnsupportedMode);
        } else {
            let sector = Sector::new(
                disk_spec,
                bat_entries,
                &sector_index,
                &sector_count,
            )?;

            let bat_entry = match bat_entries.get(sector.bat_index as usize) {
                Some(bat_entry) => bat_entry,
                None => {
                    return Err(Error::InvalidBatIndex);
                }
            };

            match *bat_entry & vhdx_bat::BAT_STATE_BIT_MASK {
                vhdx_bat::PAYLOAD_BLOCK_NOT_PRESENT
                | vhdx_bat::PAYLOAD_BLOCK_UNDEFINED
                | vhdx_bat::PAYLOAD_BLOCK_UNMAPPED
                | vhdx_bat::PAYLOAD_BLOCK_UNMAPPED_v095
                | vhdx_bat::PAYLOAD_BLOCK_ZERO => {}
                vhdx_bat::PAYLOAD_BLOCK_FULLY_PRESENT => {
                    // should we put lock here or in the calling function?
                    f.seek(SeekFrom::Start(sector.file_offset))
                        .map_err(Error::ReadSectorBlock)?;
                    f.read(
                        &mut buf[read_count
                            ..(read_count + (sector.free_sectors * SECTOR_SIZE) as usize)],
                    )
                    .map_err(Error::ReadSectorBlock)?;
                }
                vhdx_bat::PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                    return Err(Error::UnsupportedMode);
                }
                _ => {
                    return Err(Error::InvalidBatEntryState);
                }
            };
            sector_count -= sector.free_sectors;
            sector_index += sector.free_sectors;
            read_count = sector.free_bytes as usize;
        };
    }
    Ok(read_count)
}

pub fn write(
    f: &mut File,
    buf: &[u8],
    disk_spec: &DiskSpec,
    bat_offset: u64,
    bat_entries: &mut Vec<u64>,
    mut sector_index: u64,
    mut sector_count: u64,
) -> Result<usize> {
    let mut write_count: usize = 0;

    while sector_count > 0 {
        if disk_spec.has_parent {
            return Err(Error::UnsupportedMode);
        } else {
            let sector = Sector::new(
                disk_spec,
                bat_entries,
                &sector_index,
                &sector_count,
            )?;

            let bat_entry = match bat_entries.get(sector.bat_index as usize) {
                Some(bat_entry) => bat_entry,
                None => {
                    return Err(Error::InvalidBatIndex);
                }
            };

            match *bat_entry & vhdx_bat::BAT_STATE_BIT_MASK {
                vhdx_bat::PAYLOAD_BLOCK_NOT_PRESENT
                | vhdx_bat::PAYLOAD_BLOCK_UNDEFINED
                | vhdx_bat::PAYLOAD_BLOCK_UNMAPPED
                | vhdx_bat::PAYLOAD_BLOCK_UNMAPPED_v095
                | vhdx_bat::PAYLOAD_BLOCK_ZERO => {
                    let mut new_size =
                        round_up!(disk_spec.image_size, vhdx_metadata::BLOCK_SIZE_MIN as u64);
                    new_size += disk_spec.block_size as u64;
                    if new_size > size_of::<u64>() as u64 {
                        return Err(Error::InvalidDiskSize);
                    }

                    f.set_len(new_size).map_err(Error::ResizeFile)?;
                    let updated_bat_entry = sector.file_offset
                        | (vhdx_bat::PAYLOAD_BLOCK_FULLY_PRESENT & vhdx_bat::BAT_STATE_BIT_MASK);
                    bat_entries.insert(sector.bat_index as usize, updated_bat_entry);
                    // TODO: propagate
                    let _ = BatEntry::write_bat_entries(f, bat_offset, bat_entries.clone());
                }
                vhdx_bat::PAYLOAD_BLOCK_FULLY_PRESENT => {
                    if sector.file_offset < vhdx_metadata::BLOCK_SIZE_MIN as u64 {
                        break;
                    }

                    // should we put lock here or in the calling function?
                    f.seek(SeekFrom::Start(sector.file_offset))
                        .map_err(Error::ReadSectorBlock)?;
                    f.write(
                        &buf[write_count
                            ..(write_count + (sector.free_sectors * SECTOR_SIZE) as usize)],
                    )
                    .map_err(Error::ReadSectorBlock)?;
                }
                vhdx_bat::PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                    return Err(Error::UnsupportedMode);
                }
                _ => {
                    return Err(Error::InvalidBatEntryState);
                }
            };
            sector_count -= sector.free_sectors;
            sector_index += sector.free_sectors;
            write_count = sector.free_bytes as usize;
        };
    }
    Ok(write_count)
}
