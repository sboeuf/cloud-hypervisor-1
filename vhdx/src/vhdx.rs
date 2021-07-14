use crate::vhdx_bat::{BatEntry, Error as VhdxBatError};
use crate::vhdx_header::{
    Error as VhdxHeaderError, FileTypeIdentifier, RegionTableEntry, VhdxHeader,
};
use crate::vhdx_io::{self, Error as VhdxIOError};
use crate::vhdx_metadata::{DiskSpec, Error as VhdxMetadataError, MetadataTableEntry};
use libc::EINVAL;
use remain::sorted;
use std::collections::btree_map::BTreeMap;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use log::info;

const REGION1_START: u64 = 192 * 1024; // Region 1 start in Bytes
const REGION2_START: u64 = 256 * 1024; // Region 2 start in Bytes

macro_rules! div_round_up {
    ($n:expr,$d:expr) => {{
        ($n + $d - 1) / $d
    }};
}

#[sorted]
pub enum Error {
    // Failed parsing VHDX header
    ParseVhdxHeader(VhdxHeaderError),
    // Failed parsing Metadata
    ParseVhdxMetadata(VhdxMetadataError),
    // Failed parsing region entries
    ParseVhdxRegionEntry(VhdxHeaderError),
    ReadBatEntry(VhdxBatError),
    ReadFailed(VhdxIOError),
    WriteFailed(VhdxIOError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            ParseVhdxHeader(e) => write!(f, "Failed to parse VHDx Header {}", e),
            ParseVhdxMetadata(e) => write!(f, "Failed to parse VHDx metadata {}", e),
            ParseVhdxRegionEntry(e) => write!(f, "Failed to parse VHDx Region entries {}", e),
            ReadBatEntry(e) => write!(f, "Failed reading metadata {}", e),
            ReadFailed(e) => write!(f, "Failed reading sector from disk {}", e),
            WriteFailed(e) => write!(f, "Failed writing to sector on disk {}", e),
        }
    }
}

#[derive(Debug)]
pub struct Vhdx {
    file: File,
    vhdx_header: VhdxHeader,
    region_entries: BTreeMap<u64, u64>,
    bat_entry: RegionTableEntry,
    mdr_entry: RegionTableEntry,
    disk_spec: DiskSpec,
    bat_entries: Vec<u64>,
    current_offset: u64,
}

impl Vhdx {
    pub fn new(mut file: File) -> Result<Vhdx> {
        let vhdx_header = match VhdxHeader::new(&mut file) {
            Ok(vhdx_header) => vhdx_header,
            Err(e) => {
                return Err(Error::ParseVhdxHeader(e));
            }
        };

        let (bat_entry, mdr_entry, region_entries) = match RegionTableEntry::collect_entries(
            &mut file,
            REGION1_START,
            vhdx_header.clone().region_entry_count(),
        ) {
            Ok(r) => (r.0, r.1, r.2),
            Err(e) => {
                return Err(Error::ParseVhdxRegionEntry(e));
            }
        };

        let bat_entry = bat_entry.unwrap();
        let mdr_entry = mdr_entry.unwrap();

        let disk_spec = MetadataTableEntry::parse_metadata(&mut file, mdr_entry.clone())
            .map_err(Error::ParseVhdxMetadata)?;
        let bat_entries =
            BatEntry::collect_bat_entries(&mut file, disk_spec.clone(), bat_entry.clone())
                .map_err(Error::ReadBatEntry)?;

        Ok(Vhdx {
            file,
            vhdx_header,
            region_entries,
            bat_entry,
            mdr_entry,
            disk_spec,
            bat_entries,
            current_offset: 0,
        })
    }

    pub fn virtual_disk_size(&self) -> u64 {
        self.disk_spec.virtual_disk_size
    }
}

pub fn is_vhdx(f: &mut File) -> std::io::Result<bool> {
    match FileTypeIdentifier::new(f) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

impl Read for Vhdx {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        let sector_count =
            div_round_up!(buf.len() as u64, self.disk_spec.logical_sector_size as u64);
        let sector_index = self.current_offset / self.disk_spec.logical_sector_size as u64;

        for i in 0 .. buf.len()  {
            if buf[i] != b'D' {
                info!("ch={} offset={} len={} sector count={} sector index={}", buf[i], self.current_offset, buf.len(), sector_count, sector_index);
                break;
            } 
        }

        match vhdx_io::read(
            &mut self.file,
            buf,
            self.disk_spec.clone(),
            self.bat_entries.clone(),
            sector_index,
            sector_count,
        ) {
            Ok(r) => Ok(r),
            Err(e) => {
                println!("Vhdx read: {}", e);
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl Write for Vhdx {
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        self.file.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        let sector_count =
            div_round_up!(buf.len() as u64, self.disk_spec.logical_sector_size as u64);
        let sector_index = self.current_offset / self.disk_spec.logical_sector_size as u64;

        match vhdx_io::write(
            &mut self.file,
            buf,
            self.disk_spec.clone(),
            self.bat_entry.file_offset,
            &mut self.bat_entries.clone(),
            sector_index,
            sector_count,
        ) {
            Ok(r) => Ok(r),
            Err(e) => {
                println!("Vhdx write: {}", e);
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl Seek for Vhdx {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_offset: Option<u64> = match pos {
            SeekFrom::Start(off) => Some(off),
            SeekFrom::End(off) => {
                if off < 0 {
                    0i64.checked_sub(off).and_then(|increment| {
                        self.virtual_disk_size().checked_sub(increment as u64)
                    })
                } else {
                    self.virtual_disk_size().checked_add(off as u64)
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| self.current_offset.checked_sub(increment as u64))
                } else {
                    self.current_offset.checked_add(off as u64)
                }
            }
        };

        if let Some(o) = new_offset {
            if o <= self.virtual_disk_size() {
                self.current_offset = o;
                return Ok(o);
            }
        }
        Err(std::io::Error::from_raw_os_error(EINVAL))
    }
}

impl Clone for Vhdx {
    fn clone(&self) -> Self {
        Vhdx {
            file: self.file.try_clone().expect("File cloning failed"),
            vhdx_header: self.vhdx_header.clone(),
            region_entries: self.region_entries.clone(),
            bat_entry: self.bat_entry.clone(),
            mdr_entry: self.mdr_entry.clone(),
            disk_spec: self.disk_spec.clone(),
            bat_entries: self.bat_entries.clone(),
            current_offset: self.current_offset,
        }
    }
}
