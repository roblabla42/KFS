//! Multiboot Information
//!
//! Gives access to the [multiboot information structure] created by our bootloader (GRUB).
//!
//! Bootloader (GRUB) passed its address in `$ebx` when we started.
//!
//! Our bootstrap had the job of copy-ing it to a PAGE_SIZE aligned address, map it,
//! and passed it to us in `$ebx`.
//!
//! When kernel initializes we store the needed tags from this address in [`BOOT_INFO`], and we can then access
//! it at any moment by calling [`get_boot_information`].
//!
//! [multiboot information structure]: https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html#Boot-information-format
//! [`BOOT_INFO`]: self::multiboot::BOOT_INFO
//! [`get_boot_information`]: self::multiboot::get_boot_information

use alloc::string::String;
use alloc::vec::Vec;
use core::slice::Iter;
use crate::sync::Once;
use multiboot2::{BootInformation};

/// Cache of a multiboot2 module tag
#[derive(Debug)]
pub struct ModuleInformation {
    /// The start address of the module.
    start_address: usize,

    /// The end address of the module.
    end_address: usize,

    /// The module name
    name: String,
}

impl ModuleInformation {
    /// The start address of the module.
    pub fn start_address(&self) -> usize {
        self.start_address
    }

    /// The end address of the module.
    pub fn end_address(&self) -> usize {
        self.end_address
    }

    /// The name of the module.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

/// Cache multiboot2 tags needed after initialization.
#[derive(Debug)]
pub struct Multiboot2Infomation {
    /// Cache of the command line sent by multiboot2.
    command_line: Option<String>,

    /// The framebuffer informations.
    framebuffer_tag: Option<FramebufferInformation>,

    /// Cache of the modules tag sent by multiboot2.
    module_tags: Vec<ModuleInformation>,

    /// Cache of the RSDP virtual address.
    rsdp_v1_virtual_address: Option<usize>,

    /// Cache of the XSDT virtual address.
    rsdp_v2_virtual_address: Option<usize>
}

impl Multiboot2Infomation {
    /// Retrieve the frame buffer multiboot informations.
    pub fn framebuffer_tag(&self) -> Option<FramebufferInformation> {
        self.framebuffer_tag
    }

    /// Get an iterator on the cached modules.
    pub fn module_tags(&self) -> Iter<'_, ModuleInformation> {
        self.module_tags.iter()
    }

    /// Get the command line string if present.
    pub fn command_line(&self) -> Option<String> {
        self.command_line.clone()
    }

    /// Return the virtual address of the RSDPv1 header if present.
    pub fn rsdp_v1_virtual_address(&self) -> Option<usize> {
        self.rsdp_v1_virtual_address
    }

    /// Return the virtual address of the RSDPv2 header (XSDT) if present.
    pub fn rsdp_v2_virtual_address(&self) -> Option<usize> {
        self.rsdp_v2_virtual_address
    }
}

#[derive(Copy, Clone, Debug)]
/// Cache of multiboot2's framebuffer informations.
pub struct FramebufferInformation {
    /// The address of the framebuffer.
    pub address: usize,
    /// The pitch of the framebuffer.
    pub pitch: u32,
    /// The width of the framebuffer.
    pub width: u32,
    /// The height of the framebuffer.
    pub height: u32,
    /// The number of byte per pixel of the framebuffer.
    pub bpp: u8,
}


/// Stores the address of the multiboot.
static BOOT_INFO: Once<Multiboot2Infomation> = Once::new();

/// Get a pointer to the multiboot information structure.
///
/// # Panics
///
/// Panics if the Multiboot2Infomation hasn't been inited yet. This normally happens
/// right after paging is enabled.
pub fn get_boot_information() -> &'static Multiboot2Infomation {
    BOOT_INFO.r#try().expect("Multiboot2Infomation is not init'd")
}

/// Tries to get a pointer to the multiboot information structure.
///
/// Returns `None` if the Multiboot2Infomation hasn't been inited yet. This normally happens
/// right after paging is enabled.
pub fn try_get_boot_information() -> Option<&'static Multiboot2Infomation> {
    BOOT_INFO.r#try()
}

/// Initializes the boot information module, allowing the `get_boot_information`
/// functions to operate properly.
///
/// Should only be called once. Further calls will be ignored silently.
pub fn init(boot_information: BootInformation) {
    BOOT_INFO.call_once(|| {
        let framebuffer_tag = boot_information.framebuffer_tag().and_then(|tag| {
            Some(FramebufferInformation {
                address: tag.address as usize,
                pitch: tag.pitch,
                width: tag.width,
                height: tag.height,
                bpp: tag.bpp
            })
        });

        let module_tags: Vec<ModuleInformation> = boot_information.module_tags().map(|x| {
            ModuleInformation {
                start_address: x.start_address() as usize,
                end_address: x.end_address() as usize,
                name: String::from(x.name())
            }
        }).collect();

        let command_line = boot_information.command_line_tag().and_then(|x| {
            Some(String::from(x.command_line()))
        });

        // Multiboot2 hold a copy of the RSDP but have two extra fields at the begining, we are ignoring them.
        let rsdp_v1_virtual_address = boot_information.rsdp_v1_tag().and_then(|x| {
            Some((x as *const _ as usize) + 0x8)
        });

        // Multiboot2 hold a copy of the XSDT but have two extra fields at the begining, we are ignoring them.
        let rsdp_v2_virtual_address = boot_information.rsdp_v2_tag().and_then(|x| {
            Some((x as *const _ as usize) + 0x8)
        });

        Multiboot2Infomation {
            command_line,
            framebuffer_tag,
            module_tags,
            rsdp_v1_virtual_address,
            rsdp_v2_virtual_address
        }
    });
}
