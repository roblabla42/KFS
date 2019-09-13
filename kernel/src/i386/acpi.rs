//! ACPI detection
//!
//! This module is in charge of detecting the presence of ACPI and provide other part of the kernel with the data about the system.

#![allow(dead_code)]

use acpi;
use acpi::Acpi;
use acpi::AcpiHandler;
use acpi::PhysicalMapping;

use crate::sync::Once;

use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::paging;
use crate::paging::PageState;
use crate::paging::PAGE_SIZE;
use crate::paging::MappingAccessRights;
use crate::frame_allocator::PhysicalMemRegion;

use crate::utils;

use super::multiboot;

/// Stores the ACPI data
static ACPI_INFO: Once<Acpi> = Once::new();


/// Get a reference to the ACPI information.
///
/// # Panics
///
/// Panics if the module hasn't been inited yet or if ACPI isn't availaible.
pub fn get_acpi_information() -> &'static Acpi {
    ACPI_INFO.r#try().expect("Acpi is not availaible")
}

/// Tries to get a pointer to the acpi information structure.
///
/// Returns `None` if the module hasn't been inited yet or if ACPI isn't availaible.
pub fn try_get_acpi_information() -> Option<&'static Acpi> {
    ACPI_INFO.r#try()
}

/// ACPI Memory handler
struct MemoryHandler;

impl AcpiHandler for MemoryHandler {
    fn map_physical_region<T>(
        &mut self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<T> {
        let physical_address_aligned = utils::align_down(physical_address, PAGE_SIZE);

        let offset = physical_address - physical_address_aligned;
        let aligned_size = utils::align_up(offset + size, PAGE_SIZE);
    
        let physical_mem = unsafe { PhysicalMemRegion::new_unchecked(PhysicalAddress(physical_address_aligned), aligned_size) };
        let virtual_address = paging::kernel_memory::get_kernel_memory().map_phys_region(physical_mem, MappingAccessRights::k_r());

        PhysicalMapping {
            physical_start: physical_address,
            virtual_start: unsafe { core::ptr::NonNull::new_unchecked((virtual_address.0 + offset) as *mut T) },
            region_length: aligned_size,
            mapped_length: aligned_size,
        }
    }

    fn unmap_physical_region<T>(&mut self, region: PhysicalMapping<T>) {
        let virtual_address_aligned = utils::align_down(region.virtual_start.as_ptr() as usize, PAGE_SIZE);
        paging::kernel_memory::get_kernel_memory().unmap_no_dealloc(VirtualAddress(virtual_address_aligned), region.mapped_length);
    }
}

/// Parse RSDP from multiboot2 a tag.
unsafe fn parse_rsdp_tag(memory_handler: &mut MemoryHandler, rsdp_virtual_address: usize) -> bool {
    let rsdp_virtual_address_aligned = utils::align_down(rsdp_virtual_address, PAGE_SIZE);

    let offset = rsdp_virtual_address - rsdp_virtual_address_aligned;
    let rsdp_physical_address = match paging::kernel_memory::get_kernel_memory().mapping_state(VirtualAddress(rsdp_virtual_address_aligned)) {
        PageState::Present(rsdp_physical_address) => rsdp_physical_address.addr() + offset,
        _ => panic!("RSDP VIRTUAL MAPPING DOESN'T MAP TO ANYTHING???")
    };

    if let Ok(acpi) = acpi::parse_rsdp(memory_handler, rsdp_physical_address) {
        ACPI_INFO.call_once(|| {
            acpi
        });
        true
    } else {
        false
    }
}

/// Parse ACPI tables and store them.
pub unsafe fn init() {
    let mut handler = MemoryHandler;
    let mut is_init = false;

    if let Some(multiboot_info) = multiboot::try_get_boot_information() {
        if let Some(rsdp_virtual_address) = multiboot_info.rsdp_v1_virtual_address() {
            info!("Found RSDP v1 multiboot2 tag at address {:x}", rsdp_virtual_address);

            is_init = parse_rsdp_tag(&mut handler, rsdp_virtual_address);
        }
        else if let Some(rsdp_virtual_address) = multiboot_info.rsdp_v2_virtual_address() {
            info!("Found RSDP v2 multiboot2 tag at address {:x}", rsdp_virtual_address);

            is_init = parse_rsdp_tag(&mut handler, rsdp_virtual_address);
        }
    }
    if !is_init {
        if let Ok(acpi) = acpi::search_for_rsdp_bios(&mut handler) {
            info!("Found RSDP inside BIOS memory");

            ACPI_INFO.call_once(|| {
                acpi
            });

            is_init = true;
        }
    }


    if !is_init {
        info!("ACPI is not supported by this system");
    } else {
        info!("ACPI is supported by this system")
    }
}