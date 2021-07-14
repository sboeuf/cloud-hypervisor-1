extern crate log;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use remain::sorted;
use std::collections::btree_map::BTreeMap;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use uuid::Uuid;

const VHDX_SIGN: u64 = 0x656C_6966_7864_6876; //"vhdxfile"
const HEADER_SIGN: u32 = 0x6461_6568; //"head"
const REGION_SIGN: u32 = 0x6967_6572; // "regi"

const FILE_START: u64 = 0; //The first element
const HEADER1_START: u64 = 64 * 1024; //header 1 start in Bytes
const HEADER2_START: u64 = 128 * 1024; //header 2 start in Bytes
const REGION1_START: u64 = 192 * 1024; // Region 1 start in Bytes
const REGION2_START: u64 = 256 * 1024; // Region 2 start in Bytes

const HEADER_SIZE: u64 = 4 * 1024; // Each header is 64 KiB, but only first 4 kiB contains info
const REGION_SIZE: u64 = 64 * 1024; // Each region size is 64 KiB

const MAX_ENTRIES: u64 = 2047;
const REGION_ENTRY_REQUIRED: u32 = 1;

const BAT_GUID: u128 = 11023197692918435611014362394968356710; // BAT GUID in integer read in little endian
const MDR_GUID: u128 = 146921536570893805283346529412995392006; // // Metadata GUID in integer read in little endian

#[sorted]
pub enum Error {
    // Failed calculating checksum
    CalculateChecksum,
    // Multiple BAT found
    DuplicateBATEntry,
    // Multiple metadata region found
    DuplicateMDREntry,
    // Checksum does not match
    InvalidChecksum(String),
    // Entry count does not match spec
    InvalidEntryCount,
    // Header signature does not match spec
    InvalidHeaderSign,
    // Region signature does not match spec
    InvalidRegionSign,
    // Not a valid UUID
    InvalidUuid,
    // Not a VHDX sign, i.e. not a VHDX file
    InvalidVHDXSign,
    // None of the two headers are valid
    NoValidHeader,
    // Failed reading checksum
    ReadChecksum,
    // Failed reading the File Type Identifier
    ReadFileTypeIndetifier(io::Error),
    // Failed reading the Header
    ReadHeader(io::Error),
    // Failed reading a Region Table Entry
    ReadRegionTableEntry(io::Error),
    // Failed reading the Region Table Header
    ReadRegionTableHeader(io::Error),
    // Failed gathering all region entries
    RegionEntryCollectionFailed,
    // Found overlap between region entries
    RegionOverlap,
    // This region is supposed to be zero
    ReservedIsNonZero,
    // This implementation does not recognize this entry
    UnrecognizedRegionEntry,
    // Failed writing Header to the file
    WriteHeader(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            CalculateChecksum => write!(f, "Failed to calculate checksum"),
            DuplicateBATEntry => write!(f, "BAT entry is not unique"),
            DuplicateMDREntry => write!(f, "Metadata region entry is not unique"),
            InvalidChecksum(section) => write!(f, "{} checksum doesn't match", section),
            InvalidEntryCount => write!(f, "invalid entry cound"),
            InvalidHeaderSign => write!(f, "not a valid VHDX header"),
            InvalidRegionSign => write!(f, "not a valid VHDX region"),
            InvalidUuid => write!(f, "couldn't parse Uuid for region entry"),
            InvalidVHDXSign => write!(f, "not a VHDX file"),
            NoValidHeader => write!(f, "No valid header found"),
            ReadChecksum => write!(f, "cannot read checksum"),
            ReadFileTypeIndetifier(e) => write!(f, "failed to read File Type Identifier: {}", e),
            ReadHeader(e) => write!(f, "failed to read headers: {}", e),
            ReadRegionTableEntry(e) => write!(f, "failed to read region table entry: {}", e),
            ReadRegionTableHeader(e) => write!(f, "failed to read region table header: {}", e),
            RegionEntryCollectionFailed => write!(f, "failed to read region entries"),
            RegionOverlap => write!(f, "overlapping regions found"),
            ReservedIsNonZero => write!(f, "reserved region has non-zero value"),
            UnrecognizedRegionEntry => write!(f, "we do not recongize this entry"),
            WriteHeader(e) => write!(f, "failed to write header: {}", e),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FileTypeIdentifier {
    pub signature: u64,
}

impl FileTypeIdentifier {
    /// Reads the File Type Identifier structure from a reference VHDX file
    pub fn new(f: &mut File) -> Result<FileTypeIdentifier> {
        f.seek(SeekFrom::Start(FILE_START))
            .map_err(Error::ReadHeader)?;
        let signature = f.read_u64::<LittleEndian>().map_err(Error::ReadHeader)?;
        if signature != VHDX_SIGN {
            return Err(Error::InvalidVHDXSign);
        }

        Ok(FileTypeIdentifier { signature })
    }
}

#[derive(Clone, Debug)]
struct Header {
    pub signature: u32,
    pub checksum: u32,
    pub sequence_number: u64,
    pub file_write_guid: u128,
    pub data_write_guid: u128,

    pub log_guid: u128,
    pub log_version: u16,
    pub version: u16,
    pub log_length: u32,
    pub log_offset: u64,
}

impl Header {
    /// Reads the Header structure from a reference VHDX file
    pub fn new(f: &mut File, start: u64) -> Result<Header> {
        // Read the whole header in to a buffer. We will need if for calculating checksum
        let mut buffer = [0; HEADER_SIZE as usize];
        f.seek(SeekFrom::Start(start)).map_err(Error::ReadHeader)?;
        f.read_exact(&mut buffer).map_err(Error::ReadHeader)?;

        let signature = LittleEndian::read_u32(&buffer[0..4]);
        if signature != HEADER_SIGN {
            return Err(Error::InvalidHeaderSign);
        }

        let checksum = LittleEndian::read_u32(&buffer[4..8]);
        let new_checksum = calculate_checksum(&mut buffer, size_of::<u32>())?;
        if checksum != new_checksum {
            return Err(Error::InvalidChecksum(String::from("Header")));
        }

        Ok(Header {
            signature,
            checksum,
            sequence_number: LittleEndian::read_u64(&buffer[8..16]),
            file_write_guid: LittleEndian::read_u128(&buffer[16..32]),
            data_write_guid: LittleEndian::read_u128(&buffer[32..48]),
            log_guid: LittleEndian::read_u128(&buffer[48..64]),
            log_version: LittleEndian::read_u16(&buffer[64..66]),
            version: LittleEndian::read_u16(&buffer[66..68]),
            log_length: LittleEndian::read_u32(&buffer[68..72]),
            log_offset: LittleEndian::read_u64(&buffer[72..80]),
        })
    }

    fn get_header_as_buffer(&self, buffer: &mut [u8; HEADER_SIZE as usize]) {
        LittleEndian::write_u32(&mut buffer[0..4], self.signature);
        LittleEndian::write_u32(&mut buffer[4..8], self.checksum);
        LittleEndian::write_u64(&mut buffer[8..16], self.sequence_number);
        LittleEndian::write_u128(&mut buffer[16..32], self.file_write_guid);
        LittleEndian::write_u128(&mut buffer[32..48], self.data_write_guid);
        LittleEndian::write_u128(&mut buffer[48..64], self.log_guid);
        LittleEndian::write_u16(&mut buffer[64..66], self.log_version);
        LittleEndian::write_u16(&mut buffer[66..68], self.version);
        LittleEndian::write_u32(&mut buffer[68..72], self.log_length);
        LittleEndian::write_u64(&mut buffer[72..80], self.log_offset);
    }

    pub fn update_header(
        f: &mut File,
        current_header: Header,
        change_data_guid: bool,
        session_guid: u128,
        start: u64,
    ) -> Result<Header> {
        let mut buffer = [0u8; HEADER_SIZE as usize];
        let mut new_header: Header;
        let data_write_guid;

        if change_data_guid {
            let data_uuid = Uuid::new_v4();
            data_write_guid = data_uuid.as_u128();
        } else {
            data_write_guid = current_header.data_write_guid;
        }

        new_header = Header {
            signature: current_header.signature,
            checksum: 0,
            sequence_number: current_header.sequence_number + 1,
            file_write_guid: session_guid,
            data_write_guid,
            log_guid: current_header.log_guid,
            log_version: current_header.log_version,
            version: current_header.version,
            log_length: current_header.log_length,
            log_offset: current_header.log_offset,
        };

        new_header.get_header_as_buffer(&mut buffer);
        new_header.checksum = crc32c::crc32c(&buffer);
        //new_header.checksum = calculate_checksum(&mut buffer, size_of::<u32>())?;
        new_header.get_header_as_buffer(&mut buffer);

        f.seek(SeekFrom::Start(start)).map_err(Error::ReadHeader)?;
        f.write(&buffer).map_err(Error::WriteHeader)?;

        Ok(new_header)
    }
}

#[derive(Clone, Debug)]
struct RegionTableHeader {
    pub signature: u32,
    pub checksum: u32,
    pub entry_count: u32,
    pub reserved: u32,
}
impl RegionTableHeader {
    /// Reads the Region Table Header structure from a reference VHDX file
    pub fn new(f: &mut File, start: u64) -> Result<RegionTableHeader> {
        // Read the whole header in to a buffer. We will need if for calculating checksum
        let mut buffer = [0u8; REGION_SIZE as usize];
        f.seek(SeekFrom::Start(start))
            .map_err(Error::ReadRegionTableHeader)?;
        f.read_exact(&mut buffer).map_err(Error::ReadHeader)?;

        let signature = LittleEndian::read_u32(&buffer[0..4]);
        if signature != REGION_SIGN {
            return Err(Error::InvalidRegionSign);
        }

        let checksum = LittleEndian::read_u32(&buffer[4..8]);
        let new_checksum = calculate_checksum(&mut buffer, size_of::<u32>())?;
        if checksum != new_checksum {
            return Err(Error::InvalidChecksum(String::from("Region")));
        }

        let entry_count = LittleEndian::read_u32(&buffer[8..12]);
        if entry_count > 2047 {
            return Err(Error::InvalidEntryCount);
        }

        let reserved = LittleEndian::read_u32(&buffer[12..16]);
        if reserved != 0 {
            return Err(Error::ReservedIsNonZero);
        }

        Ok(RegionTableHeader {
            signature,
            checksum,
            entry_count,
            reserved,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RegionTableEntry {
    pub guid: u128,
    pub file_offset: u64,
    pub length: u32,
    pub required: u32,
}
impl RegionTableEntry {
    /// Reads one Region Entry from a Region Table index that starts from 0
    pub fn new(buffer: &[u8]) -> Result<RegionTableEntry> {
        let guid = LittleEndian::read_u128(&buffer[0..16]);
        let file_offset = LittleEndian::read_u64(&buffer[16..24]);
        let length = LittleEndian::read_u32(&buffer[24..28]);
        let required = LittleEndian::read_u32(&buffer[28..32]);

        Ok(RegionTableEntry {
            guid,
            file_offset,
            length,
            required,
        })
    }

    pub fn collect_entries(
        f: &mut File,
        region_start: u64,
        entry_count: u32,
    ) -> Result<(
        Option<RegionTableEntry>,
        Option<RegionTableEntry>,
        BTreeMap<u64, u64>,
    )> {
        let mut bat_entry: Option<RegionTableEntry> = None;
        let mut mdr_entry: Option<RegionTableEntry> = None;

        let mut bat_found = false;
        let mut mdr_found = false;
        let mut offset = 0;

        let mut region_entries = BTreeMap::new();

        let mut buffer = [0; REGION_SIZE as usize];
        f.seek(SeekFrom::Start(
            region_start + size_of::<RegionTableHeader>() as u64,
        ))
        .map_err(Error::ReadRegionTableHeader)?;
        f.read_exact(&mut buffer).map_err(Error::ReadHeader)?;

        for _ in 0..entry_count {
            match RegionTableEntry::new(&buffer[offset..offset + size_of::<RegionTableEntry>()]) {
                Ok(entry) => {
                    offset += size_of::<RegionTableEntry>();
                    let start = entry.file_offset;
                    let end = start + entry.length as u64;

                    for (_start, _end) in region_entries.iter() {
                        if !((start >= *_start) || (end <= *_end)) {
                            return Err(Error::RegionOverlap);
                        }
                    }

                    region_entries
                        .insert(entry.file_offset, entry.file_offset + entry.length as u64);

                    if entry.guid == BAT_GUID {
                        if !bat_found {
                            bat_found = true;
                            bat_entry = Some(entry);
                            continue;
                        }
                        return Err(Error::DuplicateBATEntry);
                    }

                    if entry.guid == MDR_GUID {
                        if !mdr_found {
                            mdr_found = true;
                            mdr_entry = Some(entry);
                            continue;
                        }
                        return Err(Error::DuplicateMDREntry);
                    }

                    if (entry.required & REGION_ENTRY_REQUIRED) == 1 {
                        // This implementation doesn't recognized this field.
                        // Therefore, accoding to the spec, we are throwing an error.
                        return Err(Error::UnrecognizedRegionEntry);
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
            //offset += REGION_TABLE_ENTRY_SIZE + 1;
        }

        if !bat_found || !mdr_found {
            region_entries.clear();
            return Err(Error::RegionEntryCollectionFailed);
        }

        Ok((bat_entry, mdr_entry, region_entries))
    }
}

#[derive(Clone, Debug)]
struct RegionEntry {
    start: u64,
    end: u64,
}

/// Contains the information from the header of a VHDX file
#[derive(Clone, Debug)]
pub struct VhdxHeader {
    file_type_identifier: FileTypeIdentifier,
    header_1: Header,
    header_2: Header,
    region_table_1: RegionTableHeader,
    region_table_2: RegionTableHeader,
}

impl VhdxHeader {
    /// Creates a VhdxHeader from a reference to a file
    pub fn new(f: &mut File) -> Result<VhdxHeader> {
        let file_type_identifier: FileTypeIdentifier = FileTypeIdentifier::new(f)?;
        let header_1 = Header::new(f, HEADER1_START);
        let header_2 = Header::new(f, HEADER2_START);
        let guid: u128 = 0; // TODO: take care of this
        let (header_1, header_2) = match VhdxHeader::update_headers(f, header_1, header_2, guid) {
            Ok(h) => h,
            Err(e) => return Err(e),
        };

        Ok(VhdxHeader {
            file_type_identifier,
            header_1,
            header_2,
            region_table_1: RegionTableHeader::new(f, REGION1_START)?,
            region_table_2: RegionTableHeader::new(f, REGION2_START)?,
        })
    }

    fn current_header(
        header_1: Result<Header>,
        header_2: Result<Header>,
    ) -> (u8, Result<Header>, Result<Header>) {
        let mut header1_seq_num: u64 = 0;
        let mut header2_seq_num: u64 = 0;
        let mut no_valid_header: bool = true;

        if let Ok(ref header_1) = header_1 {
            no_valid_header = false;
            header1_seq_num = header_1.sequence_number;
        }

        if let Ok(ref header_2) = header_2 {
            no_valid_header = false;
            header2_seq_num = header_2.sequence_number;
        }

        if no_valid_header {
            panic!("Get current header: {}", Error::NoValidHeader);
        } else if header1_seq_num >= header2_seq_num {
            (1, header_1, header_2)
        } else {
            (2, header_1, header_2)
        }
    }

    /// _update_header() takes two headers and update the noncurrent header with
    /// the corrent one. Returns both headers as a tuple sequenced as it received
    /// them in the parameter list.

    fn update_header(
        f: &mut File,
        header_1: Result<Header>,
        header_2: Result<Header>,
        guid: u128,
    ) -> Result<(Header, Header)> {
        let (current_header, header_1, header_2) = VhdxHeader::current_header(header_1, header_2);
        if current_header == 1 {
            match header_1 {
                Ok(header_1) => {
                    let header_2 =
                        Header::update_header(f, header_1.clone(), true, guid, HEADER2_START)?;
                    Ok((header_1, header_2))
                }
                Err(e) => Err(e),
            }
        } else {
            match header_2 {
                Ok(header_2) => {
                    let header_1 =
                        Header::update_header(f, header_2.clone(), true, guid, HEADER1_START)?;
                    Ok((header_1, header_2))
                }
                Err(e) => Err(e),
            }
        }
    }

    fn update_headers(
        f: &mut File,
        header_1: Result<Header>,
        header_2: Result<Header>,
        guid: u128,
    ) -> Result<(Header, Header)> {
        // According to the spec, update twice
        let (header_1, header_2) = VhdxHeader::update_header(f, header_1, header_2, guid)?;
        VhdxHeader::update_header(f, Ok(header_1), Ok(header_2), guid)
    }

    pub fn region_entry_count(self) -> u32 {
        self.region_table_1.entry_count
    }
}

/// Calculates the checksum of a buffer that itself containts its checksum
/// Therefore, before calculating, the existing checksum is retrieved and the
/// corresponding field is made zero. After the calculation, the existing checksum
///  is put back to the buffer.
pub fn calculate_checksum(buffer: &mut [u8], csum_offset: usize) -> Result<u32> {
    // Read the checksum in to a mutable slice
    let csum_buf = &mut buffer[csum_offset..csum_offset + 4];
    // Conver the checksum chunk in to a u32 integer
    let orig_csum = LittleEndian::read_u32(csum_buf);
    // Zeroed the checksum in the buffer. should we use Zeroize?
    LittleEndian::write_u32(csum_buf, 0);
    // Calculate the checksum on the resulted buffer
    let new_csum = crc32c::crc32c(buffer);
    // Put back the origina checksum in the buffer
    LittleEndian::write_u32(&mut buffer[csum_offset..csum_offset + 4], orig_csum);

    Ok(new_csum)
}
