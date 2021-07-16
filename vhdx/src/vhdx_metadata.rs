use crate::vhdx_header::RegionTableEntry;
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use remain::sorted;
use std::convert::TryInto;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::size_of;

const METADATA_SIGN: u64 = 0x6174_6164_6174_656D;
const METADATA_ENTRY_SIZE: usize = 32;
const METADATA_MAX_ENTRIES: u16 = 2047;
// The size including the table header and entries
const METADATA_TABLE_MAX_SIZE: usize = METADATA_ENTRY_SIZE * (METADATA_MAX_ENTRIES as usize + 1);

const METADATA_FLAGS_IS_USER: u32 = 0x01;
const METADATA_FLAGS_IS_VIRTUAL_DISK: u32 = 0x02;
const METADATA_FLAGS_IS_REQUIRED: u32 = 0x04;

pub const BLOCK_SIZE_MIN: u32 = 1024 * 1024; // 1 MiB
const BLOCK_SIZE_MAX: u32 = 256 * 1024 * 1024; // 256 MiB
const MAX_SECTORS_PER_BLOCK: u64 = 1 << 23;

const BLOCK_HAS_PARENT: u32 = 0x02; // has a parent or backing file

// GUIDs when read in Little Endian u128 integer
const METADATA_FILE_PARAMETER: u128 = 143428208870287139673581922146496636727; //"CAA16737-FA36-4D43-B3B6-33F0AA44E76B";
const METADATA_VIRTUAL_DISK_SIZE: u128 = 245846085492271402621565837099086987812; //"2FA54224-CD1B-4876-B211-5DBED83BF4B8";
const METADATA_VIRTUAL_DISK_ID: u128 = 94079244529923181982015449247999726251; //"BECA12AB-B2E6-4523-93EF-C309E000C746";
const METADATA_LOGICAL_SECTOR_SIZE: u128 = 127169626291185313037823917095022346013; //"8141BF1D-A96F-4709-BA47-F233A8FAAB5F";
const METADATA_PHYSICAL_SECTOR_SIZE: u128 = 115338139532893941197488005837198936263; //"CDA348C7-445D-4471-9CC9-E9885251C556";

// TODO: this one is still in Big Endian
const METADATA_PARENT_LOCATOR: u128 = 60312820914260793541431825701792951052; //"A8D35F2D-B30B-454D-ABF7-D3D84834AB0C";

const METADATA_FILE_PARAMETER_PRESENT: u16 = 0x01;
const METADATA_VIRTUAL_DISK_SIZE_PRESENT: u16 = 0x02;
const METADATA_VIRTUAL_DISK_ID_PRESENT: u16 = 0x04;
const METADATA_LOGICAL_SECTOR_SIZE_PRESENT: u16 = 0x08;
const METADATA_PHYSICAL_SECTOR_SIZE_PRESENT: u16 = 0x10;
const METADATA_PARENT_LOCATOR_PRESENT: u16 = 0x20;

const METADATA_ALL_PRESENT: u16 = METADATA_FILE_PARAMETER_PRESENT
    | METADATA_VIRTUAL_DISK_SIZE_PRESENT
    | METADATA_VIRTUAL_DISK_ID_PRESENT
    | METADATA_LOGICAL_SECTOR_SIZE_PRESENT
    | METADATA_PHYSICAL_SECTOR_SIZE_PRESENT;

#[sorted]
pub enum Error {
    // Block size doesn't meet spec
    InvalidBlockSize,
    // Entry size doesn't meet spec
    InvalidEntryCount,
    // Logical sector size doesn't meet spec
    InvalidLogicalSectorSize,
    // Not a know metadata item
    InvalidMetadataItem,
    // Not a metadata sign
    InvalidMetadataSign,
    // Physical sector size doesn't meet spec
    InvalidPhysicalSectorSize,
    // Not a valid value
    InvalidValue,
    // Not all required metadata are present
    MissingMetadata,
    // Failed to read metadata from file
    ReadMetadata(io::Error),
    // Found a flag not supported by this implementation
    UnsupportedFlag,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            InvalidBlockSize => write!(f, "invalid block size count"),
            InvalidEntryCount => write!(f, "invalid metadata entry count"),
            InvalidLogicalSectorSize => write!(f, "invalid logical sector size"),
            InvalidMetadataItem => write!(f, "invalid metadata ID"),
            InvalidMetadataSign => write!(f, "metadata sign doesn't match"),
            InvalidPhysicalSectorSize => write!(f, "invalid logical sector size"),
            InvalidValue => write!(f, "invalid value"),
            MissingMetadata => write!(f, "not all required metadata found"),
            ReadMetadata(e) => write!(f, "failed to read metadata headers: {}", e),
            UnsupportedFlag => write!(f, "this implementation support this metadata flag"),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct DiskSpec {
    pub disk_id: u128,
    pub image_size: u64,
    pub block_size: u32,
    pub has_parent: bool,
    pub sectors_per_block: u32,
    pub virtual_disk_size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub chunk_ratio: u64,
    pub total_sectors: u64,
}

struct MetadataTableHeader {
    signature: u64,
    _reserved: u16,
    entry_count: u16,
    _reserved2: [u8; 20],
}

impl MetadataTableHeader {
    pub fn new(buffer: &[u8]) -> Result<MetadataTableHeader> {
        let signature = LittleEndian::read_u64(&buffer[0..8]);
        if signature != METADATA_SIGN {
            return Err(Error::InvalidMetadataSign);
        }

        let reserved = LittleEndian::read_u16(&buffer[8..10]);
        let entry_count = LittleEndian::read_u16(&buffer[10..12]);
        if entry_count > METADATA_MAX_ENTRIES {
            return Err(Error::InvalidEntryCount);
        }

        Ok(MetadataTableHeader {
            signature,
            reserved,
            entry_count,
            reserved2: buffer[12..32]
                .try_into()
                .expect("slice with incorrect length"),
        })
    }
}

pub struct MetadataTableEntry {
    item_id: u128,
    offset: u32,
    length: u32,
    flag_bits: u32,
    reserved: u32,
}

impl MetadataTableEntry {
    fn new(buffer: &[u8]) -> Result<MetadataTableEntry> {
        Ok(MetadataTableEntry {
            item_id: LittleEndian::read_u128(&buffer[0..16]),
            offset: LittleEndian::read_u32(&buffer[16..20]),
            length: LittleEndian::read_u32(&buffer[20..24]),
            flag_bits: LittleEndian::read_u32(&buffer[24..28]),
            reserved: LittleEndian::read_u32(&buffer[28..32]),
        })
    }

    pub fn parse_metadata(f: &mut File, metadata_region: RegionTableEntry) -> Result<DiskSpec> {
        let mut disk_spec = DiskSpec::default();
        let mut metadata_presence: u16 = 0;
        let mut offset = 0;
        let metadata = f.metadata().map_err(Error::ReadMetadata)?;
        disk_spec.image_size = metadata.len();

        let mut buffer = [0u8; METADATA_TABLE_MAX_SIZE];
        f.seek(SeekFrom::Start(metadata_region.file_offset))
            .map_err(Error::ReadMetadata)?;
        f.read_exact(&mut buffer).map_err(Error::ReadMetadata)?;

        let metadata_header =
            MetadataTableHeader::new(&buffer[0..size_of::<MetadataTableHeader>()])?;

        offset += size_of::<MetadataTableHeader>();
        for _ in 0..metadata_header.entry_count {
            let metadata_entry =
                MetadataTableEntry::new(&buffer[offset..offset + size_of::<MetadataTableEntry>()])?;

            f.seek(SeekFrom::Start(
                metadata_region.file_offset + metadata_entry.offset as u64,
            ))
            .map_err(Error::ReadMetadata)?;
            match metadata_entry.item_id {
                METADATA_FILE_PARAMETER => {
                    disk_spec.block_size =
                        f.read_u32::<LittleEndian>().map_err(Error::ReadMetadata)?;

                    // MUST be at least 1 MiB and not greater than 256 MiB
                    if disk_spec.block_size < BLOCK_SIZE_MIN
                        && disk_spec.block_size > BLOCK_SIZE_MAX
                    {
                        return Err(Error::InvalidBlockSize);
                    }

                    // MUST be power of 2
                    if disk_spec.block_size & (disk_spec.block_size - 1) != 0 {
                        return Err(Error::InvalidBlockSize);
                    }

                    let bits = f.read_u32::<LittleEndian>().map_err(Error::ReadMetadata)?;
                    if bits & BLOCK_HAS_PARENT == 1 {
                        disk_spec.has_parent = true;
                    } else {
                        disk_spec.has_parent = false;
                    }

                    metadata_presence |= METADATA_FILE_PARAMETER_PRESENT;
                }

                METADATA_VIRTUAL_DISK_SIZE => {
                    disk_spec.virtual_disk_size =
                        f.read_u64::<LittleEndian>().map_err(Error::ReadMetadata)?;
                    metadata_presence |= METADATA_VIRTUAL_DISK_SIZE_PRESENT;
                }

                METADATA_VIRTUAL_DISK_ID => {
                    disk_spec.disk_id =
                        f.read_u128::<LittleEndian>().map_err(Error::ReadMetadata)?;
                    metadata_presence |= METADATA_VIRTUAL_DISK_ID_PRESENT;
                }

                METADATA_LOGICAL_SECTOR_SIZE => {
                    disk_spec.logical_sector_size =
                        f.read_u32::<LittleEndian>().map_err(Error::ReadMetadata)?;
                    if !(disk_spec.logical_sector_size == 512
                        || disk_spec.logical_sector_size == 4096)
                    {
                        return Err(Error::InvalidLogicalSectorSize);
                    }
                    metadata_presence |= METADATA_LOGICAL_SECTOR_SIZE_PRESENT;
                }

                METADATA_PHYSICAL_SECTOR_SIZE => {
                    disk_spec.physical_sector_size =
                        f.read_u32::<LittleEndian>().map_err(Error::ReadMetadata)?;
                    if !(disk_spec.physical_sector_size == 512
                        || disk_spec.physical_sector_size == 4096)
                    {
                        return Err(Error::InvalidPhysicalSectorSize);
                    }
                    metadata_presence |= METADATA_PHYSICAL_SECTOR_SIZE_PRESENT;
                }

                METADATA_PARENT_LOCATOR => {
                    metadata_presence |= METADATA_PARENT_LOCATOR_PRESENT;
                }

                _ => return Err(Error::InvalidMetadataItem),
            }

            if (metadata_entry.flag_bits & METADATA_FLAGS_IS_REQUIRED) == 0 {
                return Err(Error::UnsupportedFlag);
            }
            offset += size_of::<MetadataTableEntry>();
        }

        // Check if all required metadata are present
        if metadata_presence != METADATA_ALL_PRESENT {
            return Err(Error::MissingMetadata);
        }
        // Check if the virtual disk size is a multiple of the logical sector size
        if ((metadata_presence & METADATA_LOGICAL_SECTOR_SIZE_PRESENT) != 0)
            && (disk_spec.virtual_disk_size % disk_spec.logical_sector_size as u64 != 0)
        {
            return Err(Error::InvalidBlockSize);
        }

        disk_spec.sectors_per_block = MetadataTableEntry::sectors_per_block(
            disk_spec.block_size,
            disk_spec.logical_sector_size,
        )?;

        disk_spec.chunk_ratio =
            MetadataTableEntry::chunk_ratio(disk_spec.block_size, disk_spec.logical_sector_size)?;

        disk_spec.total_sectors =
            disk_spec.virtual_disk_size / disk_spec.logical_sector_size as u64;

        Ok(disk_spec)
    }

    fn sectors_per_block(block_size: u32, logical_sector_size: u32) -> Result<u32> {
        let sectors_per_block = block_size / logical_sector_size;

        if sectors_per_block & (sectors_per_block - 1) != 0 {
            return Err(Error::InvalidValue);
        }

        Ok(sectors_per_block)
    }

    fn chunk_ratio(block_size: u32, logical_sector_size: u32) -> Result<u64> {
        let chunk_ratio = (MAX_SECTORS_PER_BLOCK * logical_sector_size as u64) / block_size as u64;

        if chunk_ratio & (chunk_ratio - 1) != 0 {
            return Err(Error::InvalidValue);
        }

        Ok(chunk_ratio)
    }
}
