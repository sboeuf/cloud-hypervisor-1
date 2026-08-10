// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! iommufd-backed virtual IOMMU for the emulated ARM SMMUv3 device.
//!
//! [`Smmuv3IommuFd`] is a single object that plays both roles of the SMMUv3
//! vIOMMU:
//! - the device-facing [`HwIommuBackend`] the emulated SMMUv3 calls as the guest
//!   programs it (install/revert stage-1 HWPTs, forward invalidations), and
//! - the manager-facing [`VirtualIommuFd`] the VMM's device manager drives to
//!   register passthrough endpoints, finalize, and describe the IOMMU for ACPI.
//!
//! It owns the iommufd state (the shared [`IommufdVIommu`], the per-endpoint
//! [`IommufdVDevice`]s and the fault-forwarding thread) but is free of any VFIO
//! types: an endpoint's device is held as an [`NestedHwptDevice`]. It keeps a
//! [`Weak`] reference to the emulated device (which owns this object as its
//! backend) to avoid a reference cycle.

use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};

use devices::iommu::{Error as SmmuError, HwIommuBackend, IommuAcpiInfo, TranslationMode};
use devices::smmuv3::Smmuv3;
use iommufd_bindings::iommufd::{
    iommu_hw_info_arm_smmuv3, iommu_hwpt_arm_smmuv3, iommu_hwpt_data_type,
    iommu_hwpt_data_type_IOMMU_HWPT_DATA_ARM_SMMUV3,
    iommu_veventq_type_IOMMU_VEVENTQ_TYPE_ARM_SMMUV3, iommu_viommu_arm_smmuv3_invalidate,
    iommu_viommu_type, iommu_viommu_type_IOMMU_VIOMMU_TYPE_ARM_SMMUV3,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_ATS_NOT_SUPPORTED,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_EXEC,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_PRIV,
};
use iommufd_ioctls::{
    IommufdHwInfoData, IommufdHwptData, IommufdInvalidateData, IommufdVDevice, IommufdVEventQ,
    IommufdVIommu, NestedHwptDevice,
};
use log::{debug, error, warn};
use pci::{PasidInfo, PciBdf};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::virtual_iommu::{VirtualIommuFd, VirtualIommuFdError};

/// Depth (number of queued vEVENTs) requested for the vIOMMU's fault queue.
const VEVENTQ_DEPTH: u32 = 64;

/// Wrap a crate-specific error as the device layer's generic backend error.
fn backend_err<E: Display>(e: E) -> SmmuError {
    SmmuError::Backend(io::Error::other(e.to_string()))
}

/// A passed-through endpoint behind the vSMMU: the device (as a nested-HWPT
/// handle) and its iommufd vDevice, addressed by the guest via a StreamID.
struct Endpoint {
    device: Arc<dyn NestedHwptDevice>,
    vdevice: IommufdVDevice,
}

/// Host SMMU/device capabilities read back through `IOMMU_GET_HW_INFO`, used to
/// decide what the emulated SMMUv3 and the guest's PCI config space advertise.
struct HostSmmuInfo {
    /// Raw SMMUv3 ID registers (`idr[0..6]`).
    idr: [u32; 6],
    /// PASID capability info, `None` when the host reports no PASID support.
    pasid: Option<PasidInfo>,
    /// Whether ATS may be enabled for endpoints behind this IOMMU.
    ats_supported: bool,
}

/// The iommufd-backed SMMUv3 vIOMMU. See the module docs: it is both the
/// emulated device's [`HwIommuBackend`] and the device manager's
/// [`VirtualIommuFd`].
pub struct Smmuv3IommuFd {
    /// The emulated SMMUv3 device. Weak because the device owns this object as
    /// its backend; a strong reference would form a cycle.
    device: Weak<Mutex<Smmuv3>>,

    /// The shared vIOMMU backing the guest vSMMU (host stage-2 parent HWPT plus
    /// bypass/abort HWPTs, and the target of guest invalidations). Created lazily
    /// while attaching the first endpoint.
    viommu: Mutex<Option<Arc<IommufdVIommu>>>,

    /// Guest StreamID -> endpoint. Populated by `register_endpoint`. A StreamID
    /// with no entry has no host-backed device and is ignored by `set_translation`.
    endpoints: Mutex<HashMap<u32, Endpoint>>,

    /// Keeps the fault-forwarding reader thread alive once started.
    fault_forwarder: Mutex<Option<FaultForwarder>>,

    /// ACPI placement info for the IORT SMMUv3 node.
    acpi_info: IommuAcpiInfo,
}

impl Smmuv3IommuFd {
    /// Create the vIOMMU around an already-constructed emulated SMMUv3 device
    /// (which will own this object as its backend) and its ACPI placement info.
    pub fn new(device: &Arc<Mutex<Smmuv3>>, acpi_info: IommuAcpiInfo) -> Self {
        Self {
            device: Arc::downgrade(device),
            viommu: Mutex::new(None),
            endpoints: Mutex::new(HashMap::new()),
            fault_forwarder: Mutex::new(None),
            acpi_info,
        }
    }

    /// Query the physical SMMU's raw ID registers (`hw_info.idr[0..6]`) plus the
    /// generic per-device capabilities via any registered endpoint. All
    /// endpoints behind the same physical SMMU report the same ID registers.
    /// Returns `None` if there are no endpoints or the query fails; callers then
    /// keep the emulated defaults.
    fn host_info(&self) -> Option<HostSmmuInfo> {
        let endpoints = self.endpoints.lock().unwrap();
        let endpoint = endpoints.values().next()?;
        Self::endpoint_host_info(endpoint)
    }

    /// Query `IOMMU_GET_HW_INFO` for one endpoint.
    fn endpoint_host_info(endpoint: &Endpoint) -> Option<HostSmmuInfo> {
        let mut hw_info_data = IommufdHwInfoData::Smmuv3(iommu_hw_info_arm_smmuv3::default());
        let hw_info = endpoint
            .vdevice
            .get_device_hw_info(&mut hw_info_data)
            .inspect_err(|e| warn!("iommufd SMMUv3 failed to query host hw_info: {e}"))
            .ok()?;
        let IommufdHwInfoData::Smmuv3(info) = hw_info_data else {
            return None;
        };

        let caps = hw_info.out_capabilities;
        // A zero PASID width means the host cannot offer PASID at all; the
        // exec/priv capability bits are then meaningless and must be ignored.
        let pasid = (hw_info.out_max_pasid_log2 != 0).then(|| PasidInfo {
            max_pasid_log2: hw_info.out_max_pasid_log2,
            exec_perm: caps & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_EXEC) != 0,
            priv_mod: caps & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_PRIV) != 0,
        });

        Some(HostSmmuInfo {
            idr: info.idr,
            pasid,
            // Absence of the "not supported" bit implies ATS may be enabled.
            ats_supported: caps
                & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_ATS_NOT_SUPPORTED)
                == 0,
        })
    }

    /// Allocate an ARM SMMUv3 vEVENTQ against `viommu` and spawn a reader thread
    /// that decodes `iommu_vevent_arm_smmuv3` records (whose StreamID is already
    /// the guest's virtual one) and pushes them via [`Smmuv3::push_event`]. The
    /// thread holds a weak reference to the device and exits once it is gone.
    fn start_fault_forwarding(
        &self,
        viommu: &Arc<IommufdVIommu>,
    ) -> Result<FaultForwarder, SmmuError> {
        let veventq = viommu
            .allocate_veventq(iommu_veventq_type_IOMMU_VEVENTQ_TYPE_ARM_SMMUV3, VEVENTQ_DEPTH)
            .map_err(backend_err)?;
        let kill = EventFd::new(EFD_NONBLOCK).map_err(backend_err)?;
        let kill_reader = kill.try_clone().map_err(backend_err)?;
        let device = self.device.clone();

        let handle = thread::Builder::new()
            .name("smmuv3_veventq".to_string())
            .spawn(move || veventq_reader_loop(veventq, device, kill_reader))
            .map_err(backend_err)?;

        Ok(FaultForwarder {
            kill,
            handle: Some(handle),
        })
    }
}

impl HwIommuBackend for Smmuv3IommuFd {
    fn set_translation(&self, device_id: u32, mode: TranslationMode) -> Result<(), SmmuError> {
        let mut endpoints = self.endpoints.lock().unwrap();
        let Some(endpoint) = endpoints.get_mut(&device_id) else {
            // No host-backed device for this StreamID; nothing to program.
            debug!("iommufd SMMUv3 set_translation for unbacked SID {device_id:#x}; ignoring");
            return Ok(());
        };

        match mode {
            TranslationMode::Translate(words) => {
                // Install the guest's stage-1 STE as a nested HWPT and attach the
                // device to it. Only the first two STE words carry the stage-1
                // configuration the kernel consumes for nesting.
                if words.len() < 2 {
                    warn!("iommufd SMMUv3 translate SID {device_id:#x}: short STE; ignoring");
                    return Ok(());
                }
                debug!("iommufd SMMUv3 translate SID {device_id:#x}");
                let hwpt_data = IommufdHwptData::Smmuv3(iommu_hwpt_arm_smmuv3 {
                    ste: [words[0], words[1]],
                });
                endpoint
                    .device
                    .install_s1_hwpt(&mut endpoint.vdevice, &hwpt_data)
                    .map_err(SmmuError::Backend)?;
            }
            TranslationMode::Bypass => {
                debug!("iommufd SMMUv3 bypass SID {device_id:#x}");
                // Revert to the vIOMMU's bypass HWPT (passthrough translation).
                endpoint
                    .device
                    .uninstall_s1_hwpt(&mut endpoint.vdevice, false)
                    .map_err(SmmuError::Backend)?;
            }
            TranslationMode::Abort => {
                debug!("iommufd SMMUv3 abort SID {device_id:#x}");
                // Revert to the vIOMMU's abort HWPT (fault all DMA).
                endpoint
                    .device
                    .uninstall_s1_hwpt(&mut endpoint.vdevice, true)
                    .map_err(SmmuError::Backend)?;
            }
        }

        Ok(())
    }

    fn invalidate(&self, cmd: &[u64]) -> Result<(), SmmuError> {
        if cmd.len() < 2 {
            warn!("iommufd SMMUv3 invalidate: short command; ignoring");
            return Ok(());
        }
        // Forward the raw guest command words as a native SMMUv3 vIOMMU
        // invalidation. The kernel resolves the virtual StreamID embedded in the
        // command to the physical device via the vdevices registered on the
        // vIOMMU, so no StreamID translation is needed here.
        let viommu = self.viommu.lock().unwrap();
        let Some(viommu) = viommu.as_ref() else {
            warn!("iommufd SMMUv3 invalidate before the vIOMMU exists; ignoring");
            return Ok(());
        };
        let mut data = IommufdInvalidateData::Smmuv3(iommu_viommu_arm_smmuv3_invalidate {
            cmd: [cmd[0], cmd[1]],
        });
        let applied = viommu.invalidate_hwpt(&mut data).map_err(backend_err)?;
        if !applied {
            warn!("iommufd SMMUv3 invalidation was not applied by the host");
        }

        Ok(())
    }
}

impl VirtualIommuFd for Smmuv3IommuFd {
    fn s1_hwpt_data_type(&self) -> iommu_hwpt_data_type {
        iommu_hwpt_data_type_IOMMU_HWPT_DATA_ARM_SMMUV3
    }

    fn viommu_type(&self) -> iommu_viommu_type {
        iommu_viommu_type_IOMMU_VIOMMU_TYPE_ARM_SMMUV3
    }

    fn virt_id(&self, bdf: PciBdf) -> u64 {
        // The IORT maps a PCI RequesterID to SMMU StreamID = 256*segment + RID,
        // matching the vDevice virt_id the kernel resolves invalidations and
        // events against.
        u64::from(256 * u32::from(bdf.segment()) + (u32::from(bdf) & 0xff))
    }

    fn shared_viommu(&self) -> &Mutex<Option<Arc<IommufdVIommu>>> {
        &self.viommu
    }

    fn register_endpoint(
        &self,
        virt_id: u32,
        device: Arc<dyn NestedHwptDevice>,
        vdevice: IommufdVDevice,
    ) {
        self.endpoints
            .lock()
            .unwrap()
            .insert(virt_id, Endpoint { device, vdevice });
    }

    fn endpoint_pasid_info(&self, virt_id: u32) -> Option<PasidInfo> {
        let endpoints = self.endpoints.lock().unwrap();
        Self::endpoint_host_info(endpoints.get(&virt_id)?)?.pasid
    }

    fn ats_supported(&self) -> bool {
        // No endpoints (or a failed query) means nothing to advertise ATS for.
        self.host_info().is_some_and(|info| info.ats_supported)
    }

    fn finalize(&self) -> Result<(), VirtualIommuFdError> {
        // No shared vIOMMU means no endpoints were placed behind the vSMMU; the
        // device keeps its no-op behavior (set_translation/invalidate short-circuit).
        let Some(viommu) = self.viommu.lock().unwrap().clone() else {
            return Ok(());
        };

        // Advertise ID registers refined from the host SMMU where possible.
        if let Some(info) = self.host_info()
            && let Some(device) = self.device.upgrade()
        {
            let mut device = device.lock().unwrap();
            device.set_id_regs_from_host(&info.idr, info.ats_supported);
            debug!(
                "vSMMUv3 advertising ATS={} SSIDSIZE={} to the guest",
                info.ats_supported,
                device.ssid_bits()
            );
        }

        // Forward host stage-1 faults into the guest's event queue.
        let forwarder = self
            .start_fault_forwarding(&viommu)
            .map_err(VirtualIommuFdError::FaultForwarding)?;
        *self.fault_forwarder.lock().unwrap() = Some(forwarder);

        Ok(())
    }

    fn acpi_info(&self) -> IommuAcpiInfo {
        self.acpi_info
    }
}

/// Owns the vEVENTQ fault-forwarding reader thread; stops and joins it on drop.
struct FaultForwarder {
    kill: EventFd,
    handle: Option<JoinHandle<()>>,
}

impl Drop for FaultForwarder {
    fn drop(&mut self) {
        // Wake the reader so it observes the kill fd and returns.
        if let Err(e) = self.kill.write(1) {
            error!("SMMUv3 failed to signal vEVENTQ reader shutdown: {e}");
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Reader loop: waits on the vEVENTQ fd (and a kill fd), draining decoded
/// ARM SMMUv3 events into the guest's event queue until asked to stop or the
/// emulated device is gone.
///
/// The thread owns `veventq`, `device` and `kill` for its whole lifetime, so
/// they are taken by value even though the body only borrows them.
#[allow(clippy::needless_pass_by_value)]
fn veventq_reader_loop(mut veventq: IommufdVEventQ, device: Weak<Mutex<Smmuv3>>, kill: EventFd) {
    const VEVENTQ_TOKEN: u64 = 0;
    const KILL_TOKEN: u64 = 1;

    let epoll = match Epoll::new() {
        Ok(epoll) => epoll,
        Err(e) => {
            error!("SMMUv3 vEVENTQ reader failed to create epoll: {e}");
            return;
        }
    };
    for (fd, token) in [
        (veventq.as_raw_fd(), VEVENTQ_TOKEN),
        (kill.as_raw_fd(), KILL_TOKEN),
    ] {
        if let Err(e) = epoll.ctl(
            ControlOperation::Add,
            fd,
            EpollEvent::new(EventSet::IN, token),
        ) {
            error!("SMMUv3 vEVENTQ reader failed to register fd {fd}: {e}");
            return;
        }
    }

    let mut events = [EpollEvent::default(); 4];
    loop {
        let count = match epoll.wait(-1, &mut events) {
            Ok(count) => count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                error!("SMMUv3 vEVENTQ reader epoll wait failed: {e}");
                return;
            }
        };

        for event in events.iter().take(count) {
            match event.data() {
                KILL_TOKEN => return,
                VEVENTQ_TOKEN => match veventq.read_arm_smmuv3_events() {
                    Ok(records) => {
                        if records.is_empty() {
                            continue;
                        }
                        // The emulated device owns this reader's owner; if it is
                        // gone, there is nothing to forward to.
                        let Some(device) = device.upgrade() else {
                            return;
                        };
                        let mut device = device.lock().unwrap();
                        for (header, record) in records {
                            match record {
                                Some(evt) => device.push_event(&evt.evt),
                                None => warn!(
                                    "SMMUv3 vEVENTQ lost events before sequence {}",
                                    header.sequence
                                ),
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => warn!("SMMUv3 vEVENTQ read failed: {e}"),
                },
                other => warn!("SMMUv3 vEVENTQ reader woke on unknown token {other}"),
            }
        }
    }
}
