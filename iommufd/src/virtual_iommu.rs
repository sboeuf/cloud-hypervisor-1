// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! iommufd-backed virtual IOMMU abstraction.
//!
//! [`VirtualIommuFd`] models a guest-visible IOMMU whose translation is
//! offloaded to a physical IOMMU through iommufd nested HWPTs.

use std::sync::{Arc, Mutex};

use devices::iommu::{Error as HwIommuError, IommuAcpiInfo};
use iommufd_ioctls::{AttachHwpt, IommufdVDevice, IommufdVIommu};
use pci::{PasidInfo, PciBdf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VirtualIommuFdError {
    #[error("failed to start fault forwarding")]
    FaultForwarding(#[source] HwIommuError),
}

/// A hardware-backed virtual IOMMU driven through iommufd nested translation.
/// Implemented by the same object as [`devices::iommu::HwIommuBackend`].
pub trait VirtualIommuFd: Send + Sync {
    /// The vIOMMU type to allocate for endpoints behind this IOMMU.
    /// Whether endpoints behind this IOMMU want a vIOMMU that can host
    /// hardware queues, which only a host carrying an extension can provide.
    fn hw_queue(&self) -> bool;

    /// Guest virtual device id an endpoint is addressed by (e.g. a StreamID).
    fn virt_id(&self, bdf: PciBdf) -> u64;

    /// Shared vIOMMU handle, created lazily while binding the first endpoint.
    /// A `Mutex` rather than an attach method, to keep this trait VFIO-free.
    fn shared_viommu(&self) -> &Mutex<Option<Arc<IommufdVIommu>>>;

    /// Record an endpoint under the guest virtual id it is addressed by.
    fn register_endpoint(&self, virt_id: u32, device: Arc<dyn AttachHwpt>, vdevice: IommufdVDevice);

    /// Host PASID info for a registered endpoint, `None` if unsupported.
    /// Callable before [`Self::finalize`]: config space is built earlier.
    fn endpoint_pasid_info(&self, virt_id: u32) -> Option<PasidInfo>;

    /// Whether endpoints may use ATS. IDR0.ATS and the IORT root-complex ATS
    /// attribute must agree on this.
    fn ats_supported(&self) -> bool;

    /// Refine advertised capabilities from the host and start fault forwarding.
    fn finalize(&self) -> Result<(), VirtualIommuFdError>;

    /// ACPI placement info; the variant selects which table is emitted.
    fn acpi_info(&self) -> IommuAcpiInfo;
}
