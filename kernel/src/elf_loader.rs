//! Loads Kernel Built-ins.
//!
//! Loads the initial kernel binaries. The end-game goal is to have 5 kernel built-ins:
//!
//! - sm: The Service Manager. Plays a pivotal role for permission checking.
//! - pm: The Process Manager.
//! - loader: Loads ELFs into an address space.
//! - fs: Provides access to the FileSystem.
//! - boot: Controls the boot chain. Asks PM to start user services. Akin to the init.
//!
//! Because the 'normal' ELF loader lives in userspace in the Loader executable, kernel
//! built-ins require their own loading mechanism. On i386, we use GRUB modules to send
//! the built-ins to the kernel, and load them with a primitive ELF loader. This loader
//! does not do any dynamic loading or provide ASLR (though that is up for change)

use core::slice;
use xmas_elf::ElfFile;
use xmas_elf::program::{ProgramHeader, Type::Load, SegmentData};
use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::paging::{PAGE_SIZE, MappingAccessRights, process_memory::ProcessMemory, kernel_memory::get_kernel_memory};
use crate::frame_allocator::PhysicalMemRegion;
use crate::utils::{self, align_up};
use crate::error::KernelError;

/// Abstract representation of a Kernel Internal Process (KIP). Depending on the
/// platform, KIPs may be passed through different mechanism. For instance, on
/// IBM/PCs, they might be passed as GRUB modules, whereas on the Jetson TX1, it
/// might be passed as an INI1. This trait abstracts over those differences.
pub trait Module {
    /// Physical address defining the start of the KIP.
    fn start_address(&self) -> PhysicalAddress;
    /// Physical address defining the end of the KIP.
    fn end_address(&self) -> PhysicalAddress;
    /// Name of the KIP. Used as a process name.
    fn name(&self) -> &str;
}

/// Represents a [Module] once mapped in kernel memory
#[derive(Debug)]
pub struct MappedModule<'a> {
    /// The address of the mapping, in KernelLand.
    pub mapping_addr: VirtualAddress,
    /// The start of the module in the mapping, if it was not page aligned.
    pub start: VirtualAddress,
    /// The length of the module.
    pub len: usize,
    /// The module parsed as an ElfFile.
    pub elf: Result<ElfFile<'a>, &'static str>
}

/// Maps a grub module, which already lives in reserved physical memory, into the KernelLand.
pub fn map_module(module: &impl Module) -> MappedModule<'_> {
    let start_address_aligned = module.start_address().floor();
    // Use start_address_aligned to calculate the number of pages, to avoid an off-by-one.
    let module_len_aligned = utils::align_up(module.end_address().addr() - start_address_aligned.addr(), PAGE_SIZE);

    let mapping_addr = {
        let mut page_table = get_kernel_memory();
        let vaddr = page_table.find_virtual_space(module_len_aligned)?;

        let module_phys_location = unsafe {
            // safe, they were not tracked before
            PhysicalMemRegion::reconstruct(start_address_aligned, module_len_aligned)
        };
        page_table.map_phys_region_to(module_phys_location, vaddr, MappingAccessRights::k_r());

        vaddr
    };

    // the module offset in the mapping
    let start = mapping_addr + (start_address_aligned - module.start_address());
    let len = module.end_address() - module.start_address();

    // try parsing it as an elf
    let elf = ElfFile::new(unsafe {
        slice::from_raw_parts(start.addr() as *const u8, len)
    });

    MappedModule {
        mapping_addr,
        start,
        len,
        elf
    })
}

impl<'a> Drop for MappedModule<'a> {
    /// Unmap the module, but do not deallocate physical memory
    fn drop(&mut self) {
        get_kernel_memory().unmap_no_dealloc( self.mapping_addr,
            utils::align_up(self.len, PAGE_SIZE)
        );
    }
}

/// Gets the desired kernel access controls for a process based on the
/// .kernel_caps section in its elf
pub fn get_kacs<'a>(module: &'a MappedModule<'_>) -> Option<&'a [u8]> {
    let elf = module.elf.as_ref().expect("Failed parsing multiboot module as elf");

    elf.find_section_by_name(".kernel_caps")
        .map(|section| section.raw_data(&elf))
}

/// Loads the given kernel built-in into the given page table.
/// Returns address of entry point
pub fn load_builtin(process_memory: &mut ProcessMemory, module: &MappedModule<'_>) -> usize {
    let elf = module.elf.as_ref().expect("Failed parsing multiboot module as elf");

    // load all segments into the page_table we had above
    for ph in elf.program_iter().filter(|ph|
        ph.get_type().expect("Failed to get type of elf program header") == Load)
    {
        load_segment(process_memory, ph, &elf);
    }

    // return the entry point
    let entry_point = elf.header.pt2.entry_point();
    info!("Entry point : {:#x?}", entry_point);

    entry_point as usize
}

/// Loads an elf segment by coping file_size bytes to the right address,
/// and filling remaining with 0s.
/// This is used by NOBITS sections (.bss), this way we initialize them to 0.
#[allow(clippy::match_bool)] // more readable
fn load_segment(process_memory: &mut ProcessMemory, segment: ProgramHeader<'_>, elf_file: &ElfFile) {
    // Map the segment memory in KernelLand
    let mem_size_total = align_up(segment.mem_size() as usize, PAGE_SIZE);

    // Map as readonly if specified
    let mut flags = MappingAccessRights::USER_ACCESSIBLE;
    if segment.flags().is_read() {
        flags |= MappingAccessRights::READABLE
    };
    if segment.flags().is_write() {
        flags |= MappingAccessRights::WRITABLE
    };
    if segment.flags().is_execute() {
        flags |= MappingAccessRights::EXECUTABLE
    }

    // Create the mapping in UserLand
    let userspace_addr = VirtualAddress(segment.virtual_addr() as usize);
    process_memory.create_regular_mapping(userspace_addr, mem_size_total, flags)
        .expect("Cannot load segment");

    // Mirror it in KernelLand
    let mirror = process_memory.mirror_mapping(userspace_addr, mem_size_total)
        .expect("Cannot mirror segment to load");
    let kernel_addr = mirror.addr();

    // Copy the segment data
    match segment.get_data(elf_file).expect("Error getting elf segment data")
    {
        SegmentData::Undefined(elf_data) =>
        {
            let dest_ptr = kernel_addr.addr() as *mut u8;
            let dest = unsafe { slice::from_raw_parts_mut(dest_ptr, mem_size_total) };
            let (dest_data, dest_pad) = dest.split_at_mut(segment.file_size() as usize);

            // Copy elf data
            dest_data.copy_from_slice(elf_data);

            // Fill remaining with 0s
            for byte in dest_pad.iter_mut() {
                *byte = 0x00;
            }
        },
        x => { panic ! ("Unexpected Segment data {:?}", x) }
    }

    info!("Loaded segment - VirtAddr {:#010x}, FileSize {:#010x}, MemSize {:#010x} {}{}{}",
        segment.virtual_addr(), segment.file_size(), segment.mem_size(),
        match segment.flags().is_read()    { true => 'R', false => ' '},
        match segment.flags().is_write()   { true => 'W', false => ' '},
        match segment.flags().is_execute() { true => 'X', false => ' '},
    );

    // unmap it from KernelLand, leaving it mapped only in UserLand
    drop(mirror);
}
