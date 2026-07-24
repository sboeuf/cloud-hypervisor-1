// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! iommufd-based backends for Cloud Hypervisor's emulated IOMMUs.
//!
//! This crate holds the integration between Cloud Hypervisor's emulated IOMMU
//! devices (in the `devices` crate) and the Linux iommufd / VFIO uAPI. Keeping
//! it separate ensures the device-emulation code in `devices` stays free of
//! iommufd/vfio dependencies and does not leak those abstractions.

#[cfg(target_arch = "aarch64")]
pub mod smmuv3;
#[cfg(target_arch = "aarch64")]
pub mod virtual_iommu;
