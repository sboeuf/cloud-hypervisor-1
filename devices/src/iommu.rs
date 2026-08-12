// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared types for emulated hardware IOMMUs.

use std::io;

use thiserror::Error;

/// MMIO base and wired interrupt GSIVs for the IORT SMMUv3 node.
#[derive(Clone, Copy, Debug)]
pub struct Smmuv3AcpiInfo {
    pub base: u64,
    pub event_gsiv: u32,
    pub gerror_gsiv: u32,
    /// Always 0: IDR0.PRI is not advertised, so the guest never requests it.
    /// Present only because the IORT node has a fixed layout.
    pub pri_gsiv: u32,
    pub sync_gsiv: u32,
}

/// ACPI placement info, tagged so the generator emits the right table. Lives
/// here so the generator needs no iommufd backend compiled in.
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

/// Translation a guest programmed, as decoded by the emulating IOMMU.
/// `Translate` carries raw vendor stage-1 words forwarded to the host verbatim.
pub enum TranslationMode<'a> {
    /// Install the guest's stage-1 configuration on the host.
    Translate(&'a [u64]),
    /// Traffic passes untranslated.
    Bypass,
    /// Terminate DMA (invalid/abort configuration).
    Abort,
}

/// Backend hooks invoked by an emulated hardware IOMMU as the guest programs
/// it. The device owns the architecture, so the backend only sees decoded
/// operations carrying raw vendor words.
#[allow(unused_variables)]
pub trait HwIommuBackend: Send + Sync {
    /// Install a nested stage-1 HWPT, or switch to bypass/blocking.
    fn set_translation(&self, device_id: u32, mode: TranslationMode) -> Result<(), Error> {
        Ok(())
    }

    /// Forward a guest invalidation, as raw native command words.
    fn invalidate(&self, cmd: &[u64]) -> Result<(), Error> {
        Ok(())
    }
}

/// Ignores every operation, until the real backend is installed.
pub struct NoopHwIommuBackend;

impl HwIommuBackend for NoopHwIommuBackend {}
