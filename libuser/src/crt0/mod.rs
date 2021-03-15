//! libuser CRT0
//! This module is a minimal RT0 handling the entry point of the application.
//! It handles relocation, clean the bss and then finally call start_main.

pub mod relocation;

/// Executable entrypoint. Handle relocations and calls real_start.
#[cfg(all(target_os = "sunrise", target_arch = "x86"))]
#[naked]
#[no_mangle]
#[link_section = ".text.crt0"]
pub unsafe extern fn start() {
    llvm_asm!("
    .intel_syntax noprefix
    get_aslr_base:
        call _start_shim
    eip_pos:
        .int module_header - get_aslr_base
        // As x86 has variable instruction length, this is going to be the offset to the aslr base
        .int eip_pos - get_aslr_base
    _start_shim:
        pop eax

        // Save our thread handle passed by the kernel
        // `esi` is callee-saved
        mov esi, edx

        // Save eip_pos address
        mov ecx, eax

        // Compute ASLR base because hey we don't have a choice
        sub eax, [eax + 0x4]
        mov ebx, eax

        // Compute mod0 offset
        add ebx, [ecx]

        // Relocate the module
        push ebx
        push eax
        call relocate_self

        // Clean .bss
        push ebx
        call clean_bss

        // Init TLS
        push esi
        call init_main_thread

        call real_start
    ");
}

/// Clean module bss.
/// NOTE: Even if the bss should be cleared before calling anything in Rust, all functions used here are guaranteed to not use the bss.
#[cfg(target_os = "sunrise")]
#[no_mangle]
#[link_section = ".text.crt0"]
pub unsafe extern fn clean_bss(module_header: *const relocation::ModuleHeader) {
    let module_header_address = module_header as *mut u8;
    let module_header = &(*module_header);

    let bss_start_address = module_header_address.add(module_header.bss_start_off as usize) as *mut u8;
    let bss_end_address = module_header_address.add(module_header.bss_end_off as usize) as *mut u8;

    let count = bss_end_address as usize - bss_start_address as usize;
    core::ptr::write_bytes(bss_start_address, 0, count);
}
