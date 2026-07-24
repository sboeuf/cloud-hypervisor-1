// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! iommufd-backed virtual IOMMU abstraction.
//!
//! [`VirtualIommuFd`] models a guest-visible IOMMU whose translation is offloaded
//! to a physical IOMMU through iommufd nested HWPTs — e.g. an emulated ARM
//! SMMUv3, or (later) Intel VT-d / AMD IOMMU. It is deliberately iommufd-specific
//! (the paravirtualized virtio-iommu uses a different, mapping-based model and is
//! not covered here), and it is deliberately free of any VFIO types: the endpoint
//! is handed in as an [`iommufd_ioctls::NestedHwptDevice`], so this trait depends
//! only on iommufd.
//!
//! The VMM's device manager holds one `Arc<dyn VirtualIommuFd>` (the same object
//! also implements [`devices::iommu::HwIommuBackend`] and is installed as the
//! emulated device's backend). All methods take `&self`: the object is
//! `Arc`-shared and uses interior mutability for the state accumulated during
//! setup.

use std::sync::{Arc, Mutex};

use devices::iommu::{Error as HwIommuError, IommuAcpiInfo};
use iommufd_bindings::iommufd::{iommu_hwpt_data_type, iommu_viommu_type};
use iommufd_ioctls::{IommufdVDevice, IommufdVIommu, NestedHwptDevice};
use pci::PciBdf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VirtualIommuFdError {
    #[error("failed to start fault forwarding")]
    FaultForwarding(#[source] HwIommuError),
}

/// A hardware-backed virtual IOMMU driven through iommufd nested translation.
///
/// Implemented by the same object that implements the device-facing
/// [`devices::iommu::HwIommuBackend`], so a single value (e.g. `Smmuv3IommuFd`)
/// is both the emulated device's backend and the device manager's vIOMMU handle.
pub trait VirtualIommuFd: Send + Sync {
    /// The stage-1 HWPT data type the shared `VfioIommufd` must be created with
    /// so that endpoints behind this IOMMU get nested (stage-1) HWPTs.
    fn s1_hwpt_data_type(&self) -> iommu_hwpt_data_type;

    /// The vIOMMU type to allocate for endpoints behind this IOMMU.
    fn viommu_type(&self) -> iommu_viommu_type;

    /// The guest virtual device id an endpoint is addressed by (e.g. an SMMUv3
    /// StreamID derived from the endpoint's PCI RequesterID).
    fn virt_id(&self, bdf: PciBdf) -> u64;

    /// The shared vIOMMU handle, created lazily while binding the first endpoint.
    /// The device manager locks it and passes `&mut *guard` to
    /// `VfioDevice::new_with_iommufd*` so all endpoints share one vIOMMU. Exposed
    /// as a `Mutex` (rather than a VFIO-typed attach method) to keep this trait
    /// free of the VFIO layer.
    fn shared_viommu(&self) -> &Mutex<Option<Arc<IommufdVIommu>>>;

    /// Record a passed-through endpoint (its nested-HWPT device handle and its
    /// iommufd vDevice) under the guest virtual id it is addressed by. Called
    /// once per endpoint after its VFIO device has been created.
    fn register_endpoint(
        &self,
        virt_id: u32,
        device: Arc<dyn NestedHwptDevice>,
        vdevice: IommufdVDevice,
    );

    /// Finalize once all endpoints have been registered: refine the
    /// guest-advertised capabilities from the host and start forwarding host
    /// faults to the guest.
    fn finalize(&self) -> Result<(), VirtualIommuFdError>;

    /// ACPI placement information for the emulated IOMMU device, used to build
    /// the guest's IOMMU ACPI table (e.g. the IORT SMMUv3 node). The variant
    /// identifies which table the generator emits.
    fn acpi_info(&self) -> IommuAcpiInfo;
}
