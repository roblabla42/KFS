//! Virtio Driver
//!
//! This binary contains the common bits of a virtio driver. It implements the
//! [virtio spec 1.1](https://web.archive.org/web/20190628162805/https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html).
//!
//! It does **not** support legacy or transitional interfaces. Only the modern
//! interfaces are implemented.

#![no_std]
#![feature(underscore_const_names, slice_concat_ext)]

#[macro_use]
extern crate alloc;

use sunrise_libuser::capabilities;
use sunrise_libuser::syscalls;
use sunrise_libuser::types::ReadableEvent;
use sunrise_libuser::pci::{discover as pci_discover, PciHeader, PciDevice,
                           GeneralPciHeader,
                           CONFIG_ADDRESS as PCI_CONFIG_ADDRESS,
                           CONFIG_DATA as PCI_CONFIG_DATA};
use sunrise_libuser::pci::capabilities::{MsiXEntry, MsiXControl, Capability};

use sunrise_libuser::error::{VirtioError, Error};
use log::*;
use bitflags::bitflags;
use crate::pci::{CommonCfg, NotificationCfg, Config};
use bitfield::bitfield;
use virtqueue::VirtQueue;
use core::sync::atomic::{fence, Ordering};
use alloc::vec::Vec;

mod pci;
mod net;
mod virtqueue;

bitflags! {
    /// 2.1: Device Status field
    ///
    /// The device status field provides a simple low-level indication of the completed steps of the
    /// device initialization sequence (specified in chapter 3.1).
    struct DeviceStatus: u8 {
        /// Indicates that the guest OS has found the device and recognized it as a valid virtio
        /// device.
        const ACKNOWLEDGE = 1;
        /// Indicates that the guest OS knows how to drive the device.
        const DRIVER = 2;
        /// Indicates that something went wrong with the guest, and it has given up on the device.
        /// This could be an internal error, or the driver didn't like the device for some reason,
        /// or even a fatal error during device operation.
        const FAILED = 128;
        /// Indicates that the driver has acknowledged all the features it understands, and feature
        /// negociation is complete.
        const FEATURES_OK = 8;
        /// Indicates that the driver is set up and ready to drive the device.
        const DRIVER_OK = 4;
        /// Indicates that the device has experienced an error from which it can't recover.
        const DEVICE_NEEDS_RESET = 64;
    }
}

bitflags! {
    /// 6: Reserved Feature Bits
    struct CommonFeatures: u64 {
        /// Negotiating this feature indicates that the driver can use
        /// descriptors with the VIRTQ_DESC_F_INDIRECT flag set, as described in
        /// 2.6.5.3 Indirect Descriptors and 2.7.7 Indirect Flag: Scatter-Gather
        /// Support.
        const RING_INDIRECT_DESC = 1 << 28;
        /// This feature enables the used_event and the avail_event fields as
        /// described in 2.6.7, 2.6.8 and 2.7.10.
        const RING_EVENT_IDX = 1 << 29;
        /// This indicates compliance with this specification (Virtio 1.1),
        /// giving a simple way to detect legacy devices or drivers.
        const VERSION_1 = 1 << 32;
        /// This feature indicates that the device can be used on a platform
        /// where device access to data in memory is limited and/or translated.
        /// E.g. this is the case if the device can be located behind an IOMMU
        /// that translates bus addresses from the device into physical addresses
        /// in memory, if the device can be limited to only access certain memory
        /// addresses or if special commands such as a cache flush can be needed
        /// to synchronise data in memory with the device. Whether accesses are
        /// actually limited or translated is described by platform-specific
        /// means. If this feature bit is set to 0, then the device has same
        /// access to memory addresses supplied to it as the driver has. In
        /// particular, the device will always use physical addresses matching
        /// addresses used by the driver (typically meaning physical addresses
        /// used by the CPU) and not translated further, and can access any
        /// address supplied to it by the driver. When clear, this overrides any
        /// platform-specific description of whether device access is limited or
        /// translated in any way, e.g. whether an IOMMU may be present.
        // NOTE: If this flag is not negociated, either the device becomes a
        // backdoor, or it becomes unusable... It might be a good idea to find
        // out which.
        const ACCESS_PLATFORM = 1 << 33;
        /// This feature indicates support for the packed virtqueue layout as
        /// described in 2.7 Packed Virtqueues.
        const RING_PACKED = 1 << 34;
        /// This feature indicates that all buffers are used by the device in the
        /// same order in which they have been made available.
        const IN_ORDER = 1 << 35;
        /// This feature indicates that memory accesses by the driver and the
        /// device are ordered in a way described by the platform.
        ///
        /// If this feature bit is negotiated, the ordering in effect for any
        /// memory accesses by the driver that need to be ordered in a specific
        /// way with respect to accesses by the device is the one suitable for
        /// devices described by the platform. This implies that the driver needs
        /// to use memory barriers suitable for devices described by the
        /// platform; e.g. for the PCI transport in the case of hardware PCI
        /// devices.
        ///
        /// If this feature bit is not negotiated, then the device and driver are
        /// assumed to be implemented in software, that is they can be assumed to
        /// run on identical CPUs in an SMP configuration. Thus a weaker form of
        /// memory barriers is sufficient to yield better performance.
        const ORDER_PLATFORM = 1 << 36;
        /// This feature indicates that the device supports Single Root I/O
        /// Virtualization. Currently only PCI devices support this feature.
        const SR_IOV = 1 << 37;
        /// This feature indicates that the driver passes extra data (besides
        /// identifying the virtqueue) in its device notifications. See 2.7.23
        /// Driver notifications.
        const NOTIFICATION_DATA = 1 << 38;
    }
}

bitfield! {
    pub struct Notification(u32);
    impl Debug;
    /// Virtqueue number to be notified.
    virtqueue_idx, set_virtqueue_idx: 15, 0;
    /// Offset within the ring where the next available ring entry will be
    /// written. When VIRTIO_F_RING_PACKED has been negotiated this refers to the
    /// offset (in units of descriptor entries) within the descriptor ring where
    /// the next available descriptor will be written.
    next_off_packed, set_next_off_packed: 30, 16;
    /// Wrap Counter. With VIRTIO_F_RING_PACKED this is the wrap counter
    /// referring to the next available descriptor.
    next_wrap_packed, set_next_wrap_packed: 31;
    /// Offset within the ring where the next available ring entry will be
    /// written. When VIRTIO_F_RING_PACKED has not been negotiated this refers to
    /// the available index.
    next_off_split, set_next_off_split: 31, 16;
}


#[derive(Debug)]
pub struct VirtioDevice {
    virtio_did: u16,
    common_features: CommonFeatures,
    device: PciDevice,
    header: GeneralPciHeader,
    common_cfg: CommonCfg,
    notif_cfg: NotificationCfg,
    device_cfg: Option<Config>,
    queues: Vec<Option<VirtQueue>>,
    irq_event: ReadableEvent,
}

impl VirtioDevice {
    /// 3.1: Device Initialization
    pub fn acknowledge(&mut self) {
        self.reset();
        self.common_cfg.set_device_status(DeviceStatus::ACKNOWLEDGE);

        // Setup MSI-X vector.
        self.device.enable_msix(true).unwrap();
        let mut entry = MsiXEntry {
            // TODO: DMAR
            addr: 0xFEE0_0000,
            data: 0x0000_0033,
            ctrl: MsiXControl(0)
        };
        self.device.set_msix_message_entry(0, entry).unwrap();

        self.queues.clear();
        for i in 0..self.common_cfg.num_queues() {
            self.queues.push(None)
        }
    }

    /// 4.1.4.3: Writing a 0 to device status resets the device.
    pub fn reset(&mut self) {
        self.common_cfg.set_device_status(DeviceStatus::empty());
        while !self.common_cfg.device_status().is_empty() {
            // TODO: Schedule out?
        }
    }

    /// 4.1.5.1.3 Virtqueue Configuration
    pub fn setup_virtqueue(&mut self, virtqueue_idx: u16) {
        let mut queue = self.common_cfg.queue(virtqueue_idx);
        let size = queue.size;
        let virtqueue = VirtQueue::new(size);
        queue.desc = virtqueue.descriptor_area_dma_addr();
        queue.driver = virtqueue.driver_area_dma_addr();
        queue.device = virtqueue.device_area_dma_addr();
        queue.msix_vector = 0;
        queue.enable = true;
        self.common_cfg.set_queue(virtqueue_idx, &queue);
        self.queues[virtqueue_idx as usize] = Some(virtqueue);
    }

    /// Negociate common features.
    pub fn negociate_features(&mut self, supported_features: u64, required_features: u64, preconditions: fn(u64) -> bool) -> Result<u64, Error> {
        let device_features = self.common_cfg.device_feature_bits();

        let required_virtio_features = CommonFeatures::VERSION_1 /*| CommonFeatures::ACCESS_PLATFORM*/;

        let required_features = required_virtio_features.bits() | required_features;

        let supported_features = supported_features | required_features;

        let common_features = device_features & supported_features;

        if common_features & required_features != required_features {
            info!("Required features not set: {:x}", !common_features & required_features);
            self.common_cfg.set_device_status(DeviceStatus::FAILED);
            Err(VirtioError::FeatureNegociationFailed.into())
        } else if !preconditions(common_features) {
            info!("Preconditions not met for features: {:x}", common_features);
            self.common_cfg.set_device_status(DeviceStatus::FAILED);
            Err(VirtioError::FeatureNegociationFailed.into())
        } else {
            self.common_cfg.set_driver_features(common_features);
            self.common_cfg.set_device_status(DeviceStatus::FEATURES_OK);
            if self.common_cfg.device_status().contains(DeviceStatus::FEATURES_OK) {
                self.common_features = CommonFeatures::from_bits_truncate(common_features);
                Ok(common_features)
            } else {
                info!("Device refused our feature set! {:x}", common_features);
                self.common_cfg.set_device_status(DeviceStatus::FAILED);
                Err(VirtioError::FeatureNegociationFailed.into())
            }
        }
    }

    pub fn acquire_device_cfg(&mut self) -> Config {
        self.device_cfg.take().unwrap()
    }

    pub fn notify(&self, vq: u16) {
        if let Some(queue) = self.queues.get(vq as usize).and_then(|v| v.as_ref()) {
            // 2.6.13.6: The driver performs a suitable memory barrier to ensure
            // that it updates the idx field before checking for notification
            // suppression.
            fence(Ordering::SeqCst);

            if !queue.device_notif_suppressed() {
                let queue_notify_off = self.common_cfg.queue_notify_off(vq) as usize;
                if self.common_features.contains(CommonFeatures::NOTIFICATION_DATA) {
                    debug!("Notifying {}", vq);
                    let mut notif = Notification(0);
                    notif.set_virtqueue_idx(vq.into());
                    notif.set_next_off_split(queue.get_available_idx().into());
                    self.notif_cfg.notify_with_notification(queue_notify_off as usize, notif);
                } else {
                    debug!("Notifying {}", vq);
                    self.notif_cfg.notify_with_virtqueue(queue_notify_off as usize, vq);
                }
            } else {
                debug!("Notifications for {} suppressed", vq);
            }
        } else {
            error!("Queue {} does not exist", vq);
        }
    }

    pub fn queues(&mut self) -> &mut [Option<VirtQueue>] {
        &mut self.queues[..]
    }
}

mod ping;

fn main() {
    debug!("Virtio driver starting up");
    unsafe {
        let mapping : *mut [u8; 0x1000] = sunrise_libuser::mem::map_mmio(0xfe003000).unwrap();
        (*mapping)[4] = 1;
    }

    let virtio_devices = pci_discover()
        .filter(|device| device.vid() == 0x1AF4 && 0x1000 <= device.did() && device.did() <= 0x107F)
        ;

    let mut devices = Vec::new();

    for device in virtio_devices {
        let header = match device.header() {
            PciHeader::GeneralDevice(header) => header,
            _ => {
                info!("Unsupported device");
                continue;
            }
        };

        let virtio_did = if device.did() < 0x1040 {
            // Transitional device: use PCI subsystem id
            header.subsystem_id()
        } else {
            device.did() - 0x1040
        };

        let mut common_cfg = None;
        let mut device_cfg = None;
        let mut notify_cfg = None;
        for capability in device.capabilities() {
            match capability {
                Capability::VendorSpecific(data, size) => {
                    if let Ok(Some(cap)) = pci::Cap::read(header.bars(), &data) {
                        info!("{:?}", cap);
                        match cap {
                            pci::Cap::CommonCfg(cfg) => common_cfg = Some(cfg),
                            pci::Cap::DeviceCfg(cfg) => device_cfg = Some(cfg),
                            pci::Cap::NotifyCfg(cfg) => notify_cfg = Some(cfg),
                            cap => (),
                        }
                    } else {
                        info!("Unsupported virtio cap {:#?}", &data);
                    }
                },
                cap => info!("Capability = {:#?}", cap)
            }
        }

        match (common_cfg, device_cfg, notify_cfg) {
            (Some(common_cfg), Some(device_cfg), Some(notif_cfg)) =>
                devices.push(VirtioDevice {
                    virtio_did, device, header, common_cfg, device_cfg: Some(device_cfg),
                    common_features: CommonFeatures::empty(), notif_cfg, queues: Vec::new(),
                    irq_event: syscalls::create_interrupt_event(19, 0).unwrap()
                }),
            _ => ()
        }
    }

    for device in devices.iter_mut() {
        device.acknowledge();
    }

    for device in devices {
        match device.virtio_did {
            1 => {
                info!("Creating device");
                let mut device = net::VirtioNet::new(device);
                info!("Initializing");
                device.init().unwrap();

                info!("Pinging");
                ping::ping(device);
            },
            id => info!("Unsupported did {}", id)
        }
    }

    // event loop
    /*let man = WaitableManager::new();
    let handler = Box::new(PortHandler::<AhciInterface>::new("virtio:\0").unwrap());
    man.add_waitable(handler as Box<dyn IWaitable>);
    man.run();*/
}

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::GetSystemTick,

        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,
        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::CreateInterruptEvent,
        sunrise_libuser::syscalls::nr::QueryPhysicalAddress,
        sunrise_libuser::syscalls::nr::MapMmioRegion,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,
        sunrise_libuser::syscalls::nr::CreateSession,
    ],
    raw_caps: [
        sunrise_libuser::caps::ioport(PCI_CONFIG_ADDRESS + 0), sunrise_libuser::caps::ioport(PCI_CONFIG_ADDRESS + 1), sunrise_libuser::caps::ioport(PCI_CONFIG_ADDRESS + 2), sunrise_libuser::caps::ioport(PCI_CONFIG_ADDRESS + 3),
        sunrise_libuser::caps::ioport(PCI_CONFIG_DATA    + 0), sunrise_libuser::caps::ioport(PCI_CONFIG_DATA    + 1), sunrise_libuser::caps::ioport(PCI_CONFIG_DATA    + 2), sunrise_libuser::caps::ioport(PCI_CONFIG_DATA    + 3),
        sunrise_libuser::caps::irq_pair(19, 0x3FF)
    ]
});
