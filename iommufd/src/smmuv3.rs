// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! iommufd-backed virtual IOMMU for the emulated ARM SMMUv3 device.
//!
//! [`Smmuv3IommuFd`] is both the device-facing [`HwIommuBackend`] and the
//! manager-facing [`VirtualIommuFd`], and owns the iommufd state.

use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};

use devices::iommu::{Error as SmmuError, HwIommuBackend, IommuAcpiInfo, TranslationMode};
use devices::smmuv3::Smmuv3;
use iommufd_bindings::iommufd::{
    iommu_hw_info_arm_smmuv3, iommu_hwpt_arm_smmuv3, iommu_viommu_arm_smmuv3_invalidate,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_ATS_NOT_SUPPORTED,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_EXEC,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_PRIV,
};
use iommufd_ioctls::{
    AttachHwpt, IommufdHwInfoData, IommufdHwptData, IommufdInvalidateData, IommufdVDevice,
    IommufdVEventData, IommufdVEventQ, IommufdVIommu,
};
use log::{debug, error, warn};
use pci::{PasidInfo, PciBdf};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::virtual_iommu::{VirtualIommuFd, VirtualIommuFdError};

const VEVENTQ_DEPTH: u32 = 64;

fn backend_err<E: Display>(e: E) -> SmmuError {
    SmmuError::Backend(io::Error::other(e.to_string()))
}

/// A passed-through endpoint, addressed by the guest via a StreamID.
struct Endpoint {
    device: Arc<dyn AttachHwpt>,
    vdevice: IommufdVDevice,
}

/// Host capabilities from `IOMMU_GET_HW_INFO`, deciding what is advertised.
struct HostSmmuInfo {
    idr: [u32; 6],
    pasid: Option<PasidInfo>,
    ats_supported: bool,
}

pub struct Smmuv3IommuFd {
    /// Weak: the device owns this object as its backend.
    device: Weak<Mutex<Smmuv3>>,

    /// Created lazily with the first endpoint.
    viommu: Mutex<Option<Arc<IommufdVIommu>>>,

    /// Guest StreamID -> endpoint. A StreamID with no entry is ignored.
    endpoints: Mutex<HashMap<u32, Endpoint>>,

    fault_forwarder: Mutex<Option<FaultForwarder>>,

    acpi_info: IommuAcpiInfo,
}

impl Smmuv3IommuFd {
    pub fn new(device: &Arc<Mutex<Smmuv3>>, acpi_info: IommuAcpiInfo) -> Self {
        Self {
            device: Arc::downgrade(device),
            viommu: Mutex::new(None),
            endpoints: Mutex::new(HashMap::new()),
            fault_forwarder: Mutex::new(None),
            acpi_info,
        }
    }

    /// Queried through any endpoint: all endpoints behind the same physical
    /// SMMU report the same ID registers. `None` keeps the emulated defaults.
    fn host_info(&self) -> Option<HostSmmuInfo> {
        let endpoints = self.endpoints.lock().unwrap();
        let endpoint = endpoints.values().next()?;
        Self::endpoint_host_info(endpoint)
    }

    fn endpoint_host_info(endpoint: &Endpoint) -> Option<HostSmmuInfo> {
        let mut hw_info_data = IommufdHwInfoData::Smmuv3(iommu_hw_info_arm_smmuv3::default());
        let hw_info = endpoint
            .vdevice
            .hw_info(&mut hw_info_data)
            .inspect_err(|e| warn!("iommufd SMMUv3 failed to query host hw_info: {e}"))
            .ok()?;
        let IommufdHwInfoData::Smmuv3(info) = hw_info_data else {
            return None;
        };

        let caps = hw_info.out_capabilities;
        // A zero width means no PASID; the exec/priv bits are then meaningless.
        let pasid = (hw_info.out_max_pasid_log2 != 0).then(|| PasidInfo {
            max_pasid_log2: hw_info.out_max_pasid_log2,
            exec_perm: caps & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_EXEC) != 0,
            priv_mod: caps & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_PRIV) != 0,
        });

        Some(HostSmmuInfo {
            idr: info.idr,
            pasid,
            ats_supported: caps
                & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_ATS_NOT_SUPPORTED)
                == 0,
        })
    }

    /// Allocate a vEVENTQ against `viommu` and spawn a thread forwarding its
    /// records to the device, which the thread only holds weakly.
    fn start_fault_forwarding(
        &self,
        viommu: &Arc<IommufdVIommu>,
    ) -> Result<FaultForwarder, SmmuError> {
        let veventq = viommu
            .allocate_veventq(VEVENTQ_DEPTH)
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
            debug!("iommufd SMMUv3 set_translation for unbacked SID {device_id:#x}; ignoring");
            return Ok(());
        };

        match mode {
            TranslationMode::Translate(words) => {
                // Only the first two STE words carry the stage-1 config.
                if words.len() < 2 {
                    warn!("iommufd SMMUv3 translate SID {device_id:#x}: short STE; ignoring");
                    return Ok(());
                }
                debug!("iommufd SMMUv3 translate SID {device_id:#x}");
                let hwpt_data = IommufdHwptData::Smmuv3(iommu_hwpt_arm_smmuv3 {
                    ste: [words[0], words[1]],
                });
                // Abort while the stage-1 HWPT is swapped: installing one
                // requires the previous to be gone first.
                let device = Arc::clone(&endpoint.device);
                endpoint
                    .vdevice
                    .uninstall_s1_hwpt(device.as_ref(), true)
                    .map_err(backend_err)?;
                endpoint
                    .vdevice
                    .install_s1_hwpt(device.as_ref(), &hwpt_data)
                    .map_err(backend_err)?;
            }
            TranslationMode::Bypass => {
                debug!("iommufd SMMUv3 bypass SID {device_id:#x}");
                let device = Arc::clone(&endpoint.device);
                endpoint
                    .vdevice
                    .uninstall_s1_hwpt(device.as_ref(), false)
                    .map_err(backend_err)?;
            }
            TranslationMode::Abort => {
                debug!("iommufd SMMUv3 abort SID {device_id:#x}");
                let device = Arc::clone(&endpoint.device);
                endpoint
                    .vdevice
                    .uninstall_s1_hwpt(device.as_ref(), true)
                    .map_err(backend_err)?;
            }
        }

        Ok(())
    }

    fn invalidate(&self, cmd: &[u64]) -> Result<(), SmmuError> {
        if cmd.len() < 2 {
            warn!("iommufd SMMUv3 invalidate: short command; ignoring");
            return Ok(());
        }
        // The kernel resolves the virtual StreamID via the registered vdevices.
        let viommu = self.viommu.lock().unwrap();
        let Some(viommu) = viommu.as_ref() else {
            warn!("iommufd SMMUv3 invalidate before the vIOMMU exists; ignoring");
            return Ok(());
        };
        let mut data = IommufdInvalidateData::Smmuv3(iommu_viommu_arm_smmuv3_invalidate {
            cmd: [cmd[0], cmd[1]],
        });
        let applied = viommu.invalidate(&mut data).map_err(backend_err)?;
        if !applied {
            warn!("iommufd SMMUv3 invalidation was not applied by the host");
        }

        Ok(())
    }
}

impl VirtualIommuFd for Smmuv3IommuFd {
    fn hw_queue(&self) -> bool {
        false
    }

    fn virt_id(&self, bdf: PciBdf) -> u64 {
        // Must match the IORT mapping: StreamID = 256*segment + RID.
        u64::from(256 * u32::from(bdf.segment()) + (u32::from(bdf) & 0xff))
    }

    fn shared_viommu(&self) -> &Mutex<Option<Arc<IommufdVIommu>>> {
        &self.viommu
    }

    fn register_endpoint(
        &self,
        virt_id: u32,
        device: Arc<dyn AttachHwpt>,
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
        self.host_info().is_some_and(|info| info.ats_supported)
    }

    fn finalize(&self) -> Result<(), VirtualIommuFdError> {
        // No endpoints were placed behind the vSMMU; keep the no-op backend.
        let Some(viommu) = self.viommu.lock().unwrap().clone() else {
            return Ok(());
        };

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

struct FaultForwarder {
    kill: EventFd,
    handle: Option<JoinHandle<()>>,
}

impl Drop for FaultForwarder {
    fn drop(&mut self) {
        if let Err(e) = self.kill.write(1) {
            error!("SMMUv3 failed to signal vEVENTQ reader shutdown: {e}");
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Drains decoded SMMUv3 events into the guest's event queue until asked to
/// stop or the device is gone.
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
                VEVENTQ_TOKEN => match veventq.read_events() {
                    Ok(records) => {
                        if records.is_empty() {
                            continue;
                        }
                        let Some(device) = device.upgrade() else {
                            return;
                        };
                        let mut device = device.lock().unwrap();
                        for record in records {
                            if record.lost > 0 {
                                warn!(
                                    "SMMUv3 vEVENTQ lost {} events before sequence {}",
                                    record.lost, record.header.sequence
                                );
                                device.set_event_overflow();
                            }
                            match record.data {
                                Some(IommufdVEventData::Smmuv3(evt)) => device.push_event(&evt.evt),
                                // The queue is ARM_SMMUV3: anything else means
                                // kernel and crate disagree.
                                Some(other) => {
                                    warn!("SMMUv3 vEVENTQ yielded a foreign record: {other:?}")
                                }
                                // A tail loss, of a number the kernel cannot report.
                                None => {
                                    warn!("SMMUv3 vEVENTQ lost events at the tail");
                                    device.set_event_overflow();
                                }
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
