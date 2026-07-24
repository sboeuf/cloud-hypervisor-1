// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared types for emulated hardware IOMMUs.

use std::io;

use thiserror::Error;

/// Placement information for an emulated ARM SMMUv3, used to build the ACPI IORT
/// SMMUv3 node: its MMIO base and the four wired (SPI) interrupt GSIVs.
#[derive(Clone, Copy, Debug)]
pub struct Smmuv3AcpiInfo {
    pub base: u64,
    pub event_gsiv: u32,
    pub gerror_gsiv: u32,
    pub pri_gsiv: u32,
    pub sync_gsiv: u32,
}

/// ACPI placement information for an emulated hardware IOMMU, tagged by type so
/// the ACPI generator can emit the right table for it: IORT for ARM SMMUv3,
/// DMAR for Intel VT-d, IVRS for AMD.
///
/// Lives in `devices` (rather than the iommufd integration crate) so it is
/// visible to the ACPI generator regardless of whether the iommufd backend is
/// compiled in.
#[derive(Clone, Copy, Debug)]
pub enum IommuAcpiInfo {
    Smmuv3(Smmuv3AcpiInfo),
}

/// Error from a hardware-IOMMU backend operation.
#[derive(Debug, Error)]
pub enum Error {
    #[error("hardware IOMMU backend operation failed: {0}")]
    Backend(#[source] io::Error),
}

/// The translation outcome a guest programmed for a device, as decoded by the
/// emulating IOMMU. Vendor-neutral: `Translate` carries the raw vendor stage-1
/// configuration words (e.g. SMMUv3 STE words, VT-d context entry) that the
/// backend forwards to the host verbatim.
pub enum TranslationMode<'a> {
    /// Install the guest's stage-1 configuration on the host.
    Translate(&'a [u64]),
    /// Traffic passes untranslated.
    Bypass,
    /// Terminate DMA (invalid/abort configuration).
    Abort,
}

/// Backend hooks invoked by an emulated hardware IOMMU (ARM SMMUv3, Intel VT-d,
/// AMD) as the guest programs it.
///
/// The emulating device owns all of the IOMMU architecture — the register map,
/// queues, table walks and command decode — so the backend only ever sees
/// decoded, vendor-neutral operations carrying raw vendor payload words. This is
/// the seam where the iommufd / VFIO integration lives. Every method is a no-op
/// by default.
#[allow(unused_variables)]
pub trait HwIommuBackend: Send + Sync {
    /// Apply the decoded translation configuration for `device_id` on the host:
    /// install a nested stage-1 HWPT for `Translate`, or switch the endpoint to
    /// bypass/blocking for `Bypass`/`Abort`.
    fn set_translation(&self, device_id: u32, mode: TranslationMode) -> Result<(), Error> {
        Ok(())
    }

    /// Forward a guest invalidation to the host. `cmd` is the raw native command
    /// / descriptor words (e.g. an SMMUv3 `TLBI_*`/`CFGI_CD`/`ATC_INV`); the host
    /// iommufd invalidation uAPI consumes native words directly, so no decode is
    /// required here.
    fn invalidate(&self, cmd: &[u64]) -> Result<(), Error> {
        Ok(())
    }
}

/// A backend that ignores every operation. Used until the real (iommufd/VFIO)
/// backend is installed.
pub struct NoopHwIommuBackend;

impl HwIommuBackend for NoopHwIommuBackend {}
