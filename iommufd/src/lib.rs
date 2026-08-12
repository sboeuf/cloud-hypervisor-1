// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! iommufd-based backends for the emulated IOMMUs in the `devices` crate.
//!
//! Kept separate so `devices` stays free of iommufd/vfio dependencies.

#[cfg(target_arch = "aarch64")]
pub mod smmuv3;
#[cfg(target_arch = "aarch64")]
pub mod virtual_iommu;
