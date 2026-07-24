// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Emulated ARM SMMUv3 device.

use std::sync::{Arc, Barrier};

use log::{debug, warn};
use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError, GuestMemoryMmap,
};

use crate::iommu::{HwIommuBackend, TranslationMode};
use crate::{read_le_u32, read_le_u64, write_le_u32, write_le_u64};

type GuestMemoryMmapAtomic = GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>;

/// Size of the SMMUv3 MMIO region: two 64 KiB pages (page 0 + page 1).
pub const SMMU_V3_MMIO_SIZE: u64 = 0x2_0000;

/// Size in bytes of a single command-queue entry.
const CMDQ_ENTRY_SIZE: u64 = 16;

// --- Register offsets (page 0) ---
const IDR0: u64 = 0x0000;
const IDR1: u64 = 0x0004;
const IDR2: u64 = 0x0008;
const IDR3: u64 = 0x000c;
const IDR4: u64 = 0x0010;
const IDR5: u64 = 0x0014;
const IIDR: u64 = 0x0018;
const AIDR: u64 = 0x001c;
const CR0: u64 = 0x0020;
const CR0ACK: u64 = 0x0024;
const CR1: u64 = 0x0028;
const CR2: u64 = 0x002c;
const STATUSR: u64 = 0x0040;
const GBPA: u64 = 0x0044;
const IRQ_CTRL: u64 = 0x0050;
const IRQ_CTRLACK: u64 = 0x0054;
const GERROR: u64 = 0x0060;
const GERRORN: u64 = 0x0064;
const GERROR_IRQ_CFG0: u64 = 0x0068; // 64-bit
const GERROR_IRQ_CFG1: u64 = 0x0070;
const GERROR_IRQ_CFG2: u64 = 0x0074;
const STRTAB_BASE: u64 = 0x0080; // 64-bit
const STRTAB_BASE_CFG: u64 = 0x0088;
const CMDQ_BASE: u64 = 0x0090; // 64-bit
const CMDQ_PROD: u64 = 0x0098;
const CMDQ_CONS: u64 = 0x009c;
const EVENTQ_BASE: u64 = 0x00a0; // 64-bit
const EVENTQ_IRQ_CFG0: u64 = 0x00b0; // 64-bit
const EVENTQ_IRQ_CFG1: u64 = 0x00b8;
const EVENTQ_IRQ_CFG2: u64 = 0x00bc;
const PRIQ_BASE: u64 = 0x00c0; // 64-bit

// --- Register offsets (page 1, at 0x1_0000) ---
// EVENTQ/PRIQ producer & consumer indices live in the second 64 KiB page.
const PAGE1_BASE: u64 = 0x1_0000;
const EVENTQ_PROD: u64 = PAGE1_BASE + 0x00a8;
const EVENTQ_CONS: u64 = PAGE1_BASE + 0x00ac;
const PRIQ_PROD: u64 = PAGE1_BASE + 0x00c8;
const PRIQ_CONS: u64 = PAGE1_BASE + 0x00cc;

// --- IDR0 fields ---
const IDR0_S2P: u32 = 1 << 0; // Stage-2 translation support
const IDR0_S1P: u32 = 1 << 1; // Stage-1 translation support
const IDR0_TTF_AARCH64: u32 = 0b10 << 2; // AArch64 translation table format
const IDR0_COHACC: u32 = 1 << 4; // Coherent access to structures/queues
const IDR0_ASID16: u32 = 1 << 12; // 16-bit ASID
const IDR0_VMID16: u32 = 1 << 18; // 16-bit VMID
const IDR0_CD2L: u32 = 1 << 19; // 2-level Context Descriptor tables
const IDR0_STLEVEL_2LVL: u32 = 0b01 << 27; // 2-level Stream Table support
const IDR0_VALUE: u32 = IDR0_S1P
    | IDR0_S2P
    | IDR0_TTF_AARCH64
    | IDR0_COHACC
    | IDR0_ASID16
    | IDR0_VMID16
    | IDR0_CD2L
    | IDR0_STLEVEL_2LVL;

// --- IDR1 fields ---
const IDR1_SIDSIZE: u32 = 16; // bits [5:0]: StreamID size in bits
const IDR1_CMDQS: u32 = 19 << 21; // bits [25:21]: log2 max CMDQ entries
const IDR1_EVENTQS: u32 = 19 << 16; // bits [20:16]: log2 max EVENTQ entries
const IDR1_PRIQS: u32 = 19 << 11; // bits [15:11]: log2 max PRIQ entries
const IDR1_VALUE: u32 = IDR1_SIDSIZE | IDR1_CMDQS | IDR1_EVENTQS | IDR1_PRIQS;

// --- IDR5 fields ---
const IDR5_OAS_MASK: u32 = 0b111; // bits [2:0]: output address size
const IDR5_OAS_48BIT: u32 = 0b101; // bits [2:0]: 48-bit output address size
const IDR5_GRAN4K: u32 = 1 << 4; // 4 KiB translation granule
const IDR5_GRAN16K: u32 = 1 << 5; // 16 KiB translation granule
const IDR5_GRAN64K: u32 = 1 << 6; // 64 KiB translation granule
const IDR5_GRAN_MASK: u32 = IDR5_GRAN4K | IDR5_GRAN16K | IDR5_GRAN64K;
const IDR5_VALUE: u32 = IDR5_OAS_48BIT | IDR5_GRAN4K | IDR5_GRAN64K;

// --- CR0 / IRQ_CTRL fields ---
const CR0_SMMUEN: u32 = 1 << 0;
const CR0_EVENTQEN: u32 = 1 << 2;
const CR0_CMDQEN: u32 = 1 << 3;

// --- Event queue ---
// EVENTQ records are 32 bytes (four 64-bit words), per SMMUv3 spec 7.3.
const EVENTQ_ENTRY_SIZE: u64 = 32;
// EVENTQ_PROD.OVFLG (bit 31): set by the SMMU when a record is lost because the
// queue was full; toggled back by the guest via EVENTQ_CONS.OVACKFLG.
const EVENTQ_PROD_OVFLG: u32 = 1 << 31;

// --- Queue base field masks ---
// Q_BASE[4:0] = LOG2SIZE, Q_BASE[55:5] = base address (per SMMUv3 spec
// 6.3.26/6.3.29/..., ADDR is bits [55:5]; ADDR[4:0] are treated as zero).
const Q_BASE_LOG2SIZE_MASK: u64 = 0x1f;
const Q_BASE_ADDR_MASK: u64 = 0x00ff_ffff_ffff_ffe0;

// --- Stream table layout (SMMUv3 spec 6.3.24/6.3.25 and 5.2) ---
// STRTAB_BASE.ADDR is bits [55:6]; STRTAB_BASE_CFG holds FMT[17:16],
// SPLIT[10:6] and LOG2SIZE[5:0].
const STRTAB_BASE_ADDR_MASK: u64 = 0x00ff_ffff_ffff_ffc0;
const STRTAB_CFG_FMT_SHIFT: u32 = 16;
const STRTAB_CFG_FMT_MASK: u32 = 0b11;
const STRTAB_CFG_SPLIT_SHIFT: u32 = 6;
const STRTAB_CFG_SPLIT_MASK: u32 = 0x1f;
const STRTAB_CFG_LOG2SIZE_MASK: u32 = 0x3f;
const STRTAB_FMT_2LEVEL: u32 = 0b01;
// Smallest architectural SPLIT (6 bits / 4KB leaf tables); reserved values
// behave as this.
const STRTAB_SPLIT_MIN: u32 = 6;

// A Stream Table Entry is 64 bytes; a Level-1 Stream Table Descriptor is 8 bytes.
const STE_SIZE: u64 = 64;
const STE_WORDS: usize = 8;
const L1STD_SIZE: u64 = 8;
// L1STD.Span is bits [4:0] (0 = invalid, else 2^(Span-1) STEs); L1STD.L2Ptr is
// bits [55:6].
const L1STD_SPAN_MASK: u64 = 0x1f;
const L1STD_L2PTR_MASK: u64 = 0x00ff_ffff_ffff_ffc0;

// STE.V is word0 bit [0]; STE.Config is word0 bits [3:1].
const STE_V: u64 = 1 << 0;
const STE_CONFIG_SHIFT: u64 = 1;
const STE_CONFIG_MASK: u64 = 0b111;
// Config[2] set => traffic passes; Config == 0b100 is bypass (no stage-1),
// 0b101/0b110/0b111 select stage-1/stage-2/nested translation.
const STE_CONFIG_TRAFFIC: u8 = 0b100;
const STE_CONFIG_BYPASS: u8 = 0b100;

// --- Command opcodes (word0[7:0]) ---
const CMD_CFGI_STE: u8 = 0x03;
const CMD_CFGI_STE_RANGE: u8 = 0x04;
const CMD_CFGI_CD: u8 = 0x05;
const CMD_CFGI_CD_ALL: u8 = 0x06;
const CMD_TLBI_NH_ALL: u8 = 0x10;
const CMD_TLBI_NH_ASID: u8 = 0x11;
const CMD_TLBI_NH_VA: u8 = 0x12;
const CMD_TLBI_NH_VAA: u8 = 0x13;
const CMD_TLBI_S12_VMALL: u8 = 0x28;
const CMD_TLBI_S2_IPA: u8 = 0x2a;
const CMD_TLBI_NSNH_ALL: u8 = 0x30;
const CMD_ATC_INV: u8 = 0x40;
const CMD_SYNC: u8 = 0x46;

/// A decoded SMMUv3 command (16 bytes, two little-endian words).
#[derive(Clone, Copy, Debug)]
pub struct Command {
    pub opcode: u8,
    pub word0: u64,
    pub word1: u64,
}

impl Command {
    /// StreamID field, as used by `CFGI_STE` / `ATC_INV` commands (word0[63:32]).
    pub fn stream_id(&self) -> u32 {
        (self.word0 >> 32) as u32
    }
}

/// A decoded Stream Table Entry, produced by the emulated SMMUv3 after walking
/// the guest's (linear or 2-level) stream table.
///
/// `words` holds the raw 64-byte STE so a nesting backend can hand the guest's
/// stage-1 configuration straight to the host (e.g. an iommufd nested HWPT),
/// while the decoded fields let the device decide attach vs detach without the
/// backend having to re-parse the STE.
#[derive(Clone, Copy, Debug)]
pub struct SteConfig {
    /// StreamID this entry corresponds to.
    pub sid: u32,
    /// STE.Config[3:1] — stream configuration (translate / bypass / abort).
    pub config: u8,
    /// Raw STE: 8 x little-endian 64-bit words (an STE is 64 bytes).
    pub words: [u64; STE_WORDS],
}

/// Does this STE.Config select a translating configuration (stage-1, stage-2 or
/// nested) rather than abort or bypass?
fn ste_config_translates(config: u8) -> bool {
    config & STE_CONFIG_TRAFFIC != 0 && config != STE_CONFIG_BYPASS
}

/// Interrupt source groups for the SMMUv3 wired (SPI) interrupts.
pub struct Smmuv3Interrupts {
    pub event: Arc<dyn InterruptSourceGroup>,
    pub gerror: Arc<dyn InterruptSourceGroup>,
    pub pri: Arc<dyn InterruptSourceGroup>,
    pub sync: Arc<dyn InterruptSourceGroup>,
}

/// Emulated ARM SMMUv3 device.
pub struct Smmuv3 {
    id: String,

    // Advertised ID registers (IDR0/IDR1/IDR5). Default to safe emulated values
    // and can be refined from the host SMMU's hardware info via
    // [`Smmuv3::set_id_regs`] so the guest driver negotiates compatible
    // features for nested translation.
    idr0: u32,
    idr1: u32,
    idr5: u32,

    // Control / status registers.
    cr0: u32,
    cr0ack: u32,
    cr1: u32,
    cr2: u32,
    gbpa: u32,
    irq_ctrl: u32,
    irq_ctrlack: u32,
    gerror: u32,
    gerrorn: u32,

    // Stream table.
    strtab_base: u64,
    strtab_base_cfg: u32,

    // Command queue.
    cmdq_base: u64,
    cmdq_prod: u32,
    cmdq_cons: u32,

    // Event queue.
    eventq_base: u64,
    eventq_prod: u32,
    eventq_cons: u32,

    // PRI queue.
    priq_base: u64,
    priq_prod: u32,
    priq_cons: u32,

    // MSI/IRQ config registers (stored but unused for wired-SPI mode).
    gerror_irq_cfg0: u64,
    eventq_irq_cfg0: u64,

    mem: GuestMemoryMmapAtomic,
    interrupts: Smmuv3Interrupts,
    backend: Arc<dyn HwIommuBackend>,
}

impl Smmuv3 {
    /// Construct an emulated SMMUv3 device.
    pub fn new(
        id: String,
        mem: GuestMemoryMmapAtomic,
        interrupts: Smmuv3Interrupts,
        backend: Arc<dyn HwIommuBackend>,
    ) -> Self {
        Smmuv3 {
            id,
            idr0: IDR0_VALUE,
            idr1: IDR1_VALUE,
            idr5: IDR5_VALUE,
            cr0: 0,
            cr0ack: 0,
            cr1: 0,
            cr2: 0,
            gbpa: 0,
            irq_ctrl: 0,
            irq_ctrlack: 0,
            gerror: 0,
            gerrorn: 0,
            strtab_base: 0,
            strtab_base_cfg: 0,
            cmdq_base: 0,
            cmdq_prod: 0,
            cmdq_cons: 0,
            eventq_base: 0,
            eventq_prod: 0,
            eventq_cons: 0,
            priq_base: 0,
            priq_prod: 0,
            priq_cons: 0,
            gerror_irq_cfg0: 0,
            eventq_irq_cfg0: 0,
            mem,
            interrupts,
            backend,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Replace the backend after construction.
    ///
    /// The device is created early (before VFIO/iommufd setup) with a no-op
    /// backend, then upgraded to the real iommufd-backed one once the
    /// passed-through endpoints have been bound. See the two-phase backend
    /// injection in the VMM's device manager.
    pub fn set_backend(&mut self, backend: Arc<dyn HwIommuBackend>) {
        self.backend = backend;
    }

    /// Override the advertised IDR0/IDR1/IDR5 values.
    ///
    /// Called during two-phase setup with values derived from the host SMMU's
    /// hardware info, so the guest driver only negotiates features the physical
    /// IOMMU actually supports under nested translation. The defaults set in
    /// [`Smmuv3::new`] remain a safe fallback when no host info is available.
    pub fn set_id_regs(&mut self, idr0: u32, idr1: u32, idr5: u32) {
        self.idr0 = idr0;
        self.idr1 = idr1;
        self.idr5 = idr5;
    }

    /// Refine the advertised ID registers from the host SMMU's raw IDR registers
    /// (`hw_info.idr[0..6]`), conservatively so the guest never negotiates a
    /// feature the physical IOMMU cannot honor under nested translation:
    ///
    /// - IDR0: keep the emulated feature set but drop optional features
    ///   (coherent access, 16-bit ASID/VMID, 2-level CD/stream tables) the host
    ///   lacks.
    /// - IDR1: kept fully emulated — StreamID size and the CMDQ/EVENTQ/PRIQ
    ///   sizes are the emulation's own choice (those queues live in guest memory
    ///   and are serviced here, not by host hardware).
    /// - IDR5: clamp the output address size to the host's and intersect the
    ///   supported translation granules with the host's.
    ///
    /// Falls back to leaving a field at its emulated default when the host does
    /// not narrow it.
    pub fn set_id_regs_from_host(&mut self, host_idr: &[u32; 6]) {
        let (h0, h5) = (host_idr[0], host_idr[5]);

        let mut idr0 = IDR0_VALUE;
        for bit in [IDR0_COHACC, IDR0_ASID16, IDR0_VMID16, IDR0_CD2L] {
            if h0 & bit == 0 {
                idr0 &= !bit;
            }
        }
        if h0 & IDR0_STLEVEL_2LVL == 0 {
            idr0 &= !IDR0_STLEVEL_2LVL;
        }

        // OAS: advertise the smaller of the emulated and host output sizes.
        let oas = (IDR5_VALUE & IDR5_OAS_MASK).min(h5 & IDR5_OAS_MASK);
        // Granules: only those both the emulation and the host support. If the
        // host reports none of them (unexpected), keep the emulated set.
        let mut granules = IDR5_VALUE & h5 & IDR5_GRAN_MASK;
        if granules == 0 {
            granules = IDR5_VALUE & IDR5_GRAN_MASK;
        }
        let idr5 = (IDR5_VALUE & !(IDR5_OAS_MASK | IDR5_GRAN_MASK)) | oas | granules;

        self.set_id_regs(idr0, self.idr1, idr5);
    }

    /// Read a register value, ignoring access width.
    fn read_reg(&self, offset: u64) -> u64 {
        match offset {
            IDR0 => self.idr0 as u64,
            IDR1 => self.idr1 as u64,
            IDR2 | IDR3 | IDR4 => 0,
            IDR5 => self.idr5 as u64,
            IIDR => 0,
            AIDR => 0, // SMMUv3.0
            CR0 => self.cr0 as u64,
            CR0ACK => self.cr0ack as u64,
            CR1 => self.cr1 as u64,
            CR2 => self.cr2 as u64,
            STATUSR => 0,
            GBPA => self.gbpa as u64,
            IRQ_CTRL => self.irq_ctrl as u64,
            IRQ_CTRLACK => self.irq_ctrlack as u64,
            GERROR => self.gerror as u64,
            GERRORN => self.gerrorn as u64,
            GERROR_IRQ_CFG0 => self.gerror_irq_cfg0,
            GERROR_IRQ_CFG0_HI => self.gerror_irq_cfg0 >> 32,
            STRTAB_BASE => self.strtab_base,
            STRTAB_BASE_HI => self.strtab_base >> 32,
            STRTAB_BASE_CFG => self.strtab_base_cfg as u64,
            CMDQ_BASE => self.cmdq_base,
            CMDQ_BASE_HI => self.cmdq_base >> 32,
            CMDQ_PROD => self.cmdq_prod as u64,
            CMDQ_CONS => self.cmdq_cons as u64,
            EVENTQ_BASE => self.eventq_base,
            EVENTQ_BASE_HI => self.eventq_base >> 32,
            EVENTQ_IRQ_CFG0 => self.eventq_irq_cfg0,
            EVENTQ_IRQ_CFG0_HI => self.eventq_irq_cfg0 >> 32,
            EVENTQ_PROD => self.eventq_prod as u64,
            EVENTQ_CONS => self.eventq_cons as u64,
            PRIQ_BASE => self.priq_base,
            PRIQ_BASE_HI => self.priq_base >> 32,
            PRIQ_PROD => self.priq_prod as u64,
            PRIQ_CONS => self.priq_cons as u64,
            _ => {
                debug!("SMMUv3 unhandled read at offset {offset:#x}");
                0
            }
        }
    }

    /// Write a register value. `len` is the access width in bytes (4 or 8).
    fn write_reg(&mut self, offset: u64, val: u64, len: usize) {
        match offset {
            CR0 => {
                self.cr0 = val as u32;
                // Acknowledge control changes immediately (enable/disable take
                // effect right away in this emulation).
                self.cr0ack = self.cr0;
            }
            CR1 => self.cr1 = val as u32,
            CR2 => self.cr2 = val as u32,
            GBPA => self.gbpa = val as u32,
            IRQ_CTRL => {
                self.irq_ctrl = val as u32;
                self.irq_ctrlack = self.irq_ctrl;
            }
            GERRORN => self.gerrorn = val as u32,
            GERROR_IRQ_CFG0 => self.gerror_irq_cfg0 = merge64(self.gerror_irq_cfg0, val, len, false),
            GERROR_IRQ_CFG0_HI => {
                self.gerror_irq_cfg0 = merge64(self.gerror_irq_cfg0, val, len, true);
            }
            GERROR_IRQ_CFG1 | GERROR_IRQ_CFG2 => {}
            STRTAB_BASE => self.strtab_base = merge64(self.strtab_base, val, len, false),
            STRTAB_BASE_HI => self.strtab_base = merge64(self.strtab_base, val, len, true),
            STRTAB_BASE_CFG => self.strtab_base_cfg = val as u32,
            CMDQ_BASE => self.cmdq_base = merge64(self.cmdq_base, val, len, false),
            CMDQ_BASE_HI => self.cmdq_base = merge64(self.cmdq_base, val, len, true),
            CMDQ_PROD => {
                self.cmdq_prod = val as u32;
                self.consume_cmdq();
            }
            CMDQ_CONS => self.cmdq_cons = val as u32,
            EVENTQ_BASE => self.eventq_base = merge64(self.eventq_base, val, len, false),
            EVENTQ_BASE_HI => self.eventq_base = merge64(self.eventq_base, val, len, true),
            EVENTQ_IRQ_CFG0 => self.eventq_irq_cfg0 = merge64(self.eventq_irq_cfg0, val, len, false),
            EVENTQ_IRQ_CFG0_HI => {
                self.eventq_irq_cfg0 = merge64(self.eventq_irq_cfg0, val, len, true);
            }
            EVENTQ_IRQ_CFG1 | EVENTQ_IRQ_CFG2 => {}
            EVENTQ_PROD => self.eventq_prod = val as u32,
            EVENTQ_CONS => self.eventq_cons = val as u32,
            PRIQ_BASE => self.priq_base = merge64(self.priq_base, val, len, false),
            PRIQ_BASE_HI => self.priq_base = merge64(self.priq_base, val, len, true),
            PRIQ_PROD => self.priq_prod = val as u32,
            PRIQ_CONS => self.priq_cons = val as u32,
            _ => debug!("SMMUv3 unhandled write at offset {offset:#x}"),
        }
    }

    /// Consume all pending commands from the command queue, dispatching each to
    /// the backend, then advance `CMDQ_CONS`.
    fn consume_cmdq(&mut self) {
        if self.cr0 & CR0_SMMUEN == 0 || self.cr0 & CR0_CMDQEN == 0 {
            return;
        }

        let log2size = (self.cmdq_base & Q_BASE_LOG2SIZE_MASK) as u32;
        // The advertised maximum queue size is 2^19 entries (IDR1.CMDQS).
        // Reject anything larger to avoid shift overflow on a malformed base.
        if log2size > 19 {
            warn!("SMMUv3 invalid CMDQ log2size {log2size}");
            return;
        }
        let base = self.cmdq_base & Q_BASE_ADDR_MASK;
        let entries = 1u32 << log2size;

        // Clone the atomic handle so the memory guard does not borrow `self`,
        // leaving us free to mutate `self` and call `self` methods below.
        let mem = self.mem.clone();
        let guard = mem.memory();

        // Bound the loop by the queue size to guard against a malformed PROD.
        for _ in 0..entries {
            if q_wrapped_idx(self.cmdq_cons, log2size) == q_wrapped_idx(self.cmdq_prod, log2size) {
                break;
            }

            let idx = (self.cmdq_cons & (entries - 1)) as u64;
            let addr = base + idx * CMDQ_ENTRY_SIZE;

            let word0 = match guard.read_obj::<u64>(GuestAddress(addr)) {
                Ok(w) => w,
                Err(e) => {
                    warn!("SMMUv3 failed to read CMDQ entry at {addr:#x}: {e}");
                    break;
                }
            };
            let word1 = guard.read_obj::<u64>(GuestAddress(addr + 8)).unwrap_or(0);

            let cmd = Command {
                opcode: (word0 & 0xff) as u8,
                word0,
                word1,
            };
            self.dispatch_command(&cmd);

            self.cmdq_cons = q_inc(self.cmdq_cons, log2size);
        }
    }

    /// Walk the guest stream table (linear or 2-level, per `STRTAB_BASE_CFG`) to
    /// locate and decode the STE for `sid`. Returns `Ok(None)` when the StreamID
    /// is out of range, the L1 descriptor is invalid, or the STE is not valid.
    fn fetch_ste(&self, sid: u32) -> Result<Option<SteConfig>, GuestMemoryError> {
        let cfg = self.strtab_base_cfg;
        let fmt = (cfg >> STRTAB_CFG_FMT_SHIFT) & STRTAB_CFG_FMT_MASK;
        let log2size = cfg & STRTAB_CFG_LOG2SIZE_MASK;
        let base = self.strtab_base & STRTAB_BASE_ADDR_MASK;

        // The StreamID must be within the configured table size.
        if u64::from(sid) >= (1u64 << log2size) {
            return Ok(None);
        }

        let mem = self.mem.clone();
        let guard = mem.memory();

        let ste_addr = if fmt == STRTAB_FMT_2LEVEL {
            // 2-level: StreamID[LOG2SIZE-1:SPLIT] indexes the L1 table of
            // L1STDs; StreamID[SPLIT-1:0] indexes the L2 table of STEs.
            let split =
                ((cfg >> STRTAB_CFG_SPLIT_SHIFT) & STRTAB_CFG_SPLIT_MASK).max(STRTAB_SPLIT_MIN);
            let l1_index = u64::from(sid >> split);
            let l2_index = u64::from(sid & ((1 << split) - 1));

            let l1std = guard.read_obj::<u64>(GuestAddress(base + l1_index * L1STD_SIZE))?;
            let span = (l1std & L1STD_SPAN_MASK) as u32;
            if span == 0 {
                // L2Ptr is invalid: all StreamIDs under this descriptor are invalid.
                return Ok(None);
            }
            // The L2 table holds 2^(Span-1) STEs.
            if l2_index >= (1u64 << (span - 1)) {
                return Ok(None);
            }
            (l1std & L1STD_L2PTR_MASK) + l2_index * STE_SIZE
        } else {
            // Linear: ADDR points straight at an array of STEs.
            base + u64::from(sid) * STE_SIZE
        };

        let mut words = [0u64; STE_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = guard.read_obj::<u64>(GuestAddress(ste_addr + (i as u64) * 8))?;
        }

        if words[0] & STE_V == 0 {
            return Ok(None);
        }
        let config = ((words[0] >> STE_CONFIG_SHIFT) & STE_CONFIG_MASK) as u8;
        Ok(Some(SteConfig { sid, config, words }))
    }

    /// Handle `CMD_CFGI_STE`: re-read the STE for the StreamID and attach or
    /// detach it on the backend accordingly.
    fn handle_cfgi_ste(&mut self, sid: u32) {
        let ste = match self.fetch_ste(sid) {
            Ok(ste) => ste,
            Err(e) => {
                warn!("SMMUv3 failed to fetch STE for SID {sid:#x}: {e}");
                self.raise_gerror();
                return;
            }
        };

        let result = match &ste {
            Some(ste) if ste_config_translates(ste.config) => {
                self.backend.set_translation(sid, TranslationMode::Translate(&ste.words))
            }
            Some(ste) if ste.config == STE_CONFIG_BYPASS => {
                self.backend.set_translation(sid, TranslationMode::Bypass)
            }
            // An absent/invalid STE (V==0) or an abort Config both terminate DMA.
            _ => self.backend.set_translation(sid, TranslationMode::Abort),
        };

        if let Err(e) = result {
            warn!("SMMUv3 backend error handling CFGI_STE for SID {sid:#x}: {e}");
            self.raise_gerror();
        }
    }

    /// Dispatch a single decoded command to the relevant backend hook.
    fn dispatch_command(&mut self, cmd: &Command) {
        let result = match cmd.opcode {
            CMD_CFGI_STE => {
                self.handle_cfgi_ste(cmd.stream_id());
                Ok(())
            }
            CMD_CFGI_STE_RANGE => {
                // Range STE-config invalidation, typically issued at init. The
                // device fetches STEs on demand at CMD_CFGI_STE, so there is no
                // cached STE state to flush here.
                debug!(
                    "SMMUv3 CFGI_STE_RANGE (SID {:#x}): no cached STE state",
                    cmd.stream_id()
                );
                Ok(())
            }
            CMD_CFGI_CD | CMD_CFGI_CD_ALL | CMD_TLBI_NH_ALL | CMD_TLBI_NH_ASID
            | CMD_TLBI_NH_VA | CMD_TLBI_NH_VAA | CMD_TLBI_S12_VMALL | CMD_TLBI_S2_IPA
            | CMD_TLBI_NSNH_ALL | CMD_ATC_INV => self.backend.invalidate(&[cmd.word0, cmd.word1]),
            CMD_SYNC => {
                self.complete_sync(cmd);
                Ok(())
            }
            other => {
                debug!("SMMUv3 ignoring command opcode {other:#x}");
                Ok(())
            }
        };

        if let Err(e) = result {
            warn!("SMMUv3 backend error for opcode {:#x}: {e}", cmd.opcode);
            self.raise_gerror();
        }
    }

    /// Handle a `CMD_SYNC`: signal completion. If the command requests an
    /// interrupt completion signal (CS == 0b01), raise the sync interrupt.
    fn complete_sync(&self, cmd: &Command) {
        const CMD_SYNC_CS_IRQ: u64 = 0b01 << 12;
        if cmd.word0 & (0b11 << 12) == CMD_SYNC_CS_IRQ
            && let Err(e) = self.interrupts.sync.trigger(0)
        {
            warn!("SMMUv3 failed to raise CMD_SYNC interrupt: {e}");
        }
    }

    /// Raise a global error via the GERROR interrupt.
    fn raise_gerror(&self) {
        if let Err(e) = self.interrupts.gerror.trigger(0) {
            warn!("SMMUv3 failed to raise GERROR interrupt: {e}");
        }
    }

    /// Push a 256-bit event record onto the guest's event queue and raise the
    /// event interrupt.
    ///
    /// Called by the fault-forwarding path (the iommufd VEVENTQ reader) with a
    /// native SMMUv3 event record whose StreamID field already carries the
    /// guest's virtual StreamID. Records are dropped (with the queue's overflow
    /// flag set) if the guest has not enabled the event queue or it is full.
    pub fn push_event(&mut self, record: &[u64; 4]) {
        // The event queue only advances while the SMMU and its EVENTQ are
        // enabled by the guest.
        if self.cr0 & CR0_SMMUEN == 0 || self.cr0 & CR0_EVENTQEN == 0 {
            warn!("SMMUv3 dropping event record: event queue not enabled");
            return;
        }

        let log2size = (self.eventq_base & Q_BASE_LOG2SIZE_MASK) as u32;
        // The advertised maximum queue size is 2^19 entries (IDR1.EVENTQS).
        if log2size > 19 {
            warn!("SMMUv3 invalid EVENTQ log2size {log2size}");
            return;
        }
        let base = self.eventq_base & Q_BASE_ADDR_MASK;
        let entries = 1u32 << log2size;

        // Queue full when the next producer index (wrap included) equals the
        // consumer: set the overflow flag and drop the record, per the spec.
        if q_wrapped_idx(q_inc(self.eventq_prod, log2size), log2size)
            == q_wrapped_idx(self.eventq_cons, log2size)
        {
            warn!("SMMUv3 event queue full; setting overflow flag");
            self.eventq_prod |= EVENTQ_PROD_OVFLG;
            return;
        }

        let idx = (self.eventq_prod & (entries - 1)) as u64;
        let addr = base + idx * EVENTQ_ENTRY_SIZE;

        // Clone the atomic handle so the guard does not borrow `self`.
        let mem = self.mem.clone();
        let guard = mem.memory();
        for (i, word) in record.iter().enumerate() {
            if let Err(e) = guard.write_obj::<u64>(*word, GuestAddress(addr + (i as u64) * 8)) {
                warn!("SMMUv3 failed to write EVENTQ record at {addr:#x}: {e}");
                return;
            }
        }

        // Advance the producer (preserving the overflow flag, which lives above
        // the wrap bit) and notify the guest.
        self.eventq_prod = q_inc(self.eventq_prod, log2size);
        if let Err(e) = self.interrupts.event.trigger(0) {
            warn!("SMMUv3 failed to raise event interrupt: {e}");
        }
    }

    /// Push a PRI record onto the PRI queue. Stubbed until PRI is implemented.
    #[allow(dead_code)]
    fn push_pri(&mut self, _record: &[u64; 2]) {
        // TODO: implement PRI queue production for ATS/PRI page requests.
        if let Err(e) = self.interrupts.pri.trigger(0) {
            warn!("SMMUv3 failed to raise PRI interrupt: {e}");
        }
    }
}

impl BusDevice for Smmuv3 {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let val = self.read_reg(offset);
        match data.len() {
            8 => write_le_u64(data, val),
            4 => write_le_u32(data, val as u32),
            _ => warn!("SMMUv3 unsupported read width {} at {offset:#x}", data.len()),
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let val = match data.len() {
            8 => read_le_u64(data),
            4 => read_le_u32(data) as u64,
            _ => {
                warn!("SMMUv3 unsupported write width {} at {offset:#x}", data.len());
                return None;
            }
        };
        self.write_reg(offset, val, data.len());
        None
    }
}

// High-half offsets for 64-bit registers accessed as two 32-bit halves.
const GERROR_IRQ_CFG0_HI: u64 = GERROR_IRQ_CFG0 + 4;
const STRTAB_BASE_HI: u64 = STRTAB_BASE + 4;
const CMDQ_BASE_HI: u64 = CMDQ_BASE + 4;
const EVENTQ_BASE_HI: u64 = EVENTQ_BASE + 4;
const EVENTQ_IRQ_CFG0_HI: u64 = EVENTQ_IRQ_CFG0 + 4;
const PRIQ_BASE_HI: u64 = PRIQ_BASE + 4;

/// Merge a write of `len` bytes into a 64-bit register value. `high` selects
/// the upper 32-bit half for 4-byte writes.
fn merge64(cur: u64, val: u64, len: usize, high: bool) -> u64 {
    if len == 8 {
        return val;
    }
    if high {
        (cur & 0x0000_0000_ffff_ffff) | (val << 32)
    } else {
        (cur & 0xffff_ffff_0000_0000) | (val & 0xffff_ffff)
    }
}

/// Extract the `{wrap, index}` bits used to compare producer and consumer.
fn q_wrapped_idx(val: u32, log2size: u32) -> u32 {
    val & ((1 << (log2size + 1)) - 1)
}

/// Increment a queue `{wrap, index}` value, toggling the wrap bit on overflow.
fn q_inc(val: u32, log2size: u32) -> u32 {
    let size = 1u32 << log2size;
    let idx = val & (size - 1);
    let wrap = val & size;
    if idx + 1 == size {
        wrap ^ size // index back to 0, flip wrap bit
    } else {
        wrap | (idx + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_q_inc_wraps() {
        // log2size = 2 => 4 entries, wrap bit at bit 2.
        assert_eq!(q_inc(0b000, 2), 0b001);
        assert_eq!(q_inc(0b011, 2), 0b100); // overflow => index 0, wrap set
        assert_eq!(q_inc(0b111, 2), 0b000); // overflow => index 0, wrap cleared
    }

    #[test]
    fn test_ste_config_translates() {
        assert!(!ste_config_translates(0b000)); // abort
        assert!(!ste_config_translates(0b011)); // abort variant
        assert!(!ste_config_translates(0b100)); // bypass
        assert!(ste_config_translates(0b101)); // stage-1
        assert!(ste_config_translates(0b110)); // stage-2
        assert!(ste_config_translates(0b111)); // nested
    }

    #[test]
    fn test_merge64_halves() {
        assert_eq!(merge64(0, 0xdead_beef, 4, false), 0x0000_0000_dead_beef);
        assert_eq!(
            merge64(0x0000_0000_dead_beef, 0xcafe, 4, true),
            0x0000_cafe_dead_beef
        );
        assert_eq!(merge64(0x1234, 0xffff_0000_1111, 8, false), 0xffff_0000_1111);
    }
}
