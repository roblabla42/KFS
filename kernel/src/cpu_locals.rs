//! CPU local storage
//!
//! We want some statics to be cpu-local (e.g. [`CURRENT_THREAD`]). We could implement this fully
//! in software, by having an area of memory that is replicated for every cpu core, where
//! statics are indexes in this memory area, and provide getters and setters to access and modify
//! the cpu-local statics.
//!
//! However this is not ideal as it is not really optimized, and pretty tedious.
//!
//! Instead we use the very common concept of Thread Local Storage (TLS), and apply it to cpu cores
//! instead of threads, and let the compiler do all the hard work for us.
//!
//! # Usage
//!
//! In the kernel you declare a cpu-local using the [#\[thread_local\] attribute] :
//!
//! ```
//! #[thread_local]
//! static MY_CPU_LOCAL: core::cell::Cell<u8> = core::cell::Cell::new(42);
//! ```
//!
//! and access it as if it was a regular static, only that each cpu core will have its own view of
//! the static.
//!
//! The compiler is responsible for generating code that will access the right address, provided
//! we configured TLS correctly.
//!
//! ##### Early boot
//!
//! Note that you can't access a cpu-local static before [`init_cpu_locals`] is called, because
//! the cpu-local areas arent' initialized yet, and this will likely result to a cpu exception
//! being raised, or UB.
//!
//! This means you can't ever access cpu-locals in early boot. If your code might be called during
//! early boot, we advise you to use [`ARE_CPU_LOCALS_INITIALIZED_YET`] to know if you're allowed
//! to access your cpu-local static, and if not return an error of some kind.
//!
//! # Inner workings
//!
//! We implement the TLS according to conventions laid out by [Ulrich Drepper's paper on TLS] which
//! is followed by LLVM and most compilers.
//!
//! Since we're running on i386, we're following variant II.
//!
//! Each cpu core's `gs` segment points to a thread local memory area where cpu-locals statics live.
//! Cpu-local statics are simply accessed through an offset from `gs`.
//! Those regions can be found in [`CPU_LOCAL_REGIONS`].
//!
//! The linker is in charge of creating an ELF segment of type `PT_TLS` where an initialization image
//! for cpu local regions can be found, and is meant to be copy-pasted for every ~~thread we create~~
//! cpu core we have.
//!
//! ##### Segmentation
//!
//! Each core gets its own [GDT]. In each of these there is a `KTls` segment which points to this
//! core's cpu-local area, and which is meant to be loaded into `gs`.
//!
//! Because userspace might want to use Thread Local Storage too, and also needs `gs` to point to its
//! thread local area (see [`set_thread_area`]), we swap the segment `gs` points to everytime
//! we enter and leave the kernel in [`trap_gate_asm`], from `UTls_Elf` to `KTls` and back.
//!
//! TLS on x86 are really weird. It uses the variant II, where offsets must be *subtracted* from `gs`,
//! even though segmentation only supports *adding* offsets. The only way to make them work is to have
//! `gs` segment's limit be `0xffffffff`, effectively spanning the whole address space, and when
//! the cpu will add a "negative" (e.g. `0xfffffffc` for -4) offset, it will treat it as an unsigned
//! huge positive offset, which when added to `gs`'s base will "wrap around" the address space,
//! and effectively end up 4 bytes behind `gs`'s base.
//!
//! Illustration:
//!
//! ![cpu backflip](https://raw.githubusercontent.com/sunriseos/SunriseOS/master/kernel/res/cpu_locals_segmentation_doc.gif)
//!
//! ##### dtv and `__tls_get_addr`
//!
//! We're the kernel, and we don't do dynamic loading (no loadable kernel modules).
//! Because of this, we know our TLS model will be static (either Initial Exec or Local Exec).
//! Those models always access thread-locals directly via `gs`, and always short-circuit the dtv.
//!
//! So we don't even bother allocating a dtv array at all. Neither do we define a `__tls_get_addr`
//! function.
//!
//! [`CURRENT_THREAD`]: crate::scheduler::CURRENT_THREAD
//! [`init_cpu_locals`]: init_cpu_locals
//! [`ARE_CPU_LOCALS_INITIALIZED_YET`]: ARE_CPU_LOCALS_INITIALIZED_YET
//! [Ulrich Drepper's paper on TLS]: https://web.archive.org/web/20190710135250/https://akkadia.org/drepper/tls.pdf
//! [`CPU_LOCAL_REGIONS`]: crate::cpu_locals::CPU_LOCAL_REGIONS
//! [GDT]: crate::i386::gdt
//! [`set_thread_area`]: crate::syscalls::set_thread_area
//! [#\[thread_local\] attribute]: https://github.com/rust-lang/rust/issues/10310

use crate::i386::multiboot;
use crate::elf_loader::map_grub_module;
use crate::i386::gdt::{GDT, GdtIndex};
use sunrise_libutils::div_ceil;
use xmas_elf::program::{Type, SegmentData};
use alloc::alloc::{alloc_zeroed, dealloc};
use core::mem::align_of;
use core::alloc::Layout;
use core::mem::size_of;
use alloc::vec::Vec;
use crate::sync::Once;
use core::sync::atomic::{AtomicBool, Ordering};
use core::fmt::Debug;

/// Use this if your code might run in an early boot stage to know if you're
/// allowed to access a cpu-local variable. Accessing one when this is false is UB.
///
/// Always true after [`init_cpu_locals`] have been called.
pub static ARE_CPU_LOCALS_INITIALIZED_YET: AtomicBool = AtomicBool::new(false);

/// Array of cpu local regions, copied from the initialization image in kernel's ELF.
///
/// One per cpu core.
static CPU_LOCAL_REGIONS: Once<Vec<CpuLocalRegion>> = Once::new();

/// Address that should be put in `KTls` segment's base.
/// The limit should be `0xffffffff`.
///
/// Used for creating a core's GDT, before starting it.
///
/// # Panics
///
/// Panics if `cpu_id` is greater than the `cpu_count` that was supplied to [`init_cpu_locals`].
pub fn get_cpu_locals_ptr_for_core(cpu_id: usize) -> *const u8 {
    CPU_LOCAL_REGIONS.r#try()
        .expect("CPU_LOCAL_REGIONS not initialized")
        .get(cpu_id)
        .unwrap_or_else(|| panic!("cpu locals not initialized for cpu id {}", cpu_id))
        .tcb() as *const ThreadControlBlock as *const u8
}

/// Initializes cpu locals during early boot stage.
///
/// * Maps the kernel's ELF to get our `PT_TLS` program header information, including the TLS
///   initialization image.
/// * Allocates an array of `cpu_count` cpu local regions and stores them in [CPU_LOCAL_REGIONS].
/// * Makes this core's `KTls` segment point to `CPU_LOCAL_REGIONS[0]`'s [`ThreadControlBlock`].
///
/// # Panics
///
/// * Failed to map kernel's ELF.
/// * Failed to get kernel ELF's TLS initialization image.
pub fn init_cpu_locals(cpu_count: usize) {
    debug_assert!(cpu_count > 0, "You can't have 0 cpu cores - I'm running code therefor I am");

    CPU_LOCAL_REGIONS.call_once(|| {
        // map our own ELF so that we can access our PT_TLS
        let mapped_kernel_elf = multiboot::try_get_boot_information()
            .and_then(|info| info.module_tags().next())
            .and_then(|module| map_grub_module(module).ok())
            .expect("cpu_locals: cannot get kernel elf");
        let kernel_elf = mapped_kernel_elf.elf.as_ref()
            .expect("cpu_locals: module 0 is not kernel elf");

        // find the PT_TLS header
        let tls_program_header = kernel_elf.program_iter()
            .find(|p_header|
                p_header.get_type().ok().map(|p_header_type|
                    match p_header_type {
                        Type::Tls => true,
                        _ => false
                    }
                ).unwrap_or(false)
            )
            .expect("cpu_locals: kernel elf has no PT_TLS program header");

        // get our tls initialisation image at header.p_offset, header.p_filesz
        let tls_init_image = match tls_program_header.get_data(kernel_elf)
            .expect("cpu_locals: cannot get PT_TLS content") {
            SegmentData::Undefined(tls_data) => tls_data,
            x => panic!("PT_TLS: Unexpected Segment data {:?}", x)
        };

        // create one cpu local region per cpu from the initialisation image
        let mut cpu_local_regions = Vec::with_capacity(cpu_count);
        for _ in 0..cpu_count {
            cpu_local_regions.push(
                CpuLocalRegion::allocate(
                    tls_init_image,
                    tls_program_header.mem_size() as usize,
                    tls_program_header.align() as usize
                )
            );
        }

        // make gs point to the first cpu local region.
        let mut gdt = GDT.r#try()
            .expect("GDT not initialized")
            .lock();
        gdt.table[GdtIndex::KTls as usize].set_base(
            cpu_local_regions[0].tcb() as *const _ as usize as u32
        );
        gdt.commit(None, None, None, None, None, None);

        cpu_local_regions
    });

    // yes, they are 😌
    ARE_CPU_LOCALS_INITIALIZED_YET.store(true, Ordering::SeqCst);
}

/// The `round` function, as defined in section 3.0:
///
/// ```text
///     round(x,y) = y * ⌈x/y⌉
/// ```
///
/// Just a poorly-named `align_up`.
fn tls_align_up(x: usize, y: usize) -> usize {
    y * div_ceil(x, y)
}

/// Elf TLS TCB
///
/// The variant II leaves the specification of the ThreadControlBlock (TCB) to the implementor,
/// with the only requirement that the first word in the TCB, pointed by `tp`, contains its own
/// address, i.e. is a pointer to itself (GNU variant).
///
/// We don't need to store anything else in the TCB, it's just the self pointer.
#[repr(C)]
#[derive(Debug)]
struct ThreadControlBlock {
    /// Pointer containing its own address.
    tp_self_ptr: *const ThreadControlBlock,
}

/// Represents an allocated cpu local region.
///
/// Because cpu regions have a really specific layout, we don't use Box and instead interact with
/// the allocator directly. This type is the equivalent of a Box, it stores the pointer to the
/// allocated memory, and deallocates it on Drop.
struct CpuLocalRegion {
    /// Pointer to the allocated memory
    ptr: usize,
    /// Layout of the allocated memory. Used when deallocating.
    layout: Layout,
    /// Offset of the TCB in this allocation.
    tcb_offset: usize,
}

impl CpuLocalRegion {
    /// Returns a pointer to the [ThreadControlBlock] in the allocated region.
    /// All cpu-local arithmetic are done relative to this pointer.
    ///
    /// For TLS to work, the value stored at this address should be the address itself, i.e.
    /// having a pointer pointing to itself.
    fn tcb(&self) -> &ThreadControlBlock {
        unsafe {
            // safe: - guaranteed to be aligned, and still in the allocation,
            //       - no one should ever have a mut reference to the ThreadControlBlock after its
            //         initialisation.
            &*((self.ptr + self.tcb_offset) as *const ThreadControlBlock)
        }
    }

    /// Allocates a CpuLocalRegion.
    ///
    /// The region's content is copied from the TLS initialisation image described by `block_src`,
    /// padded with 0s for `block_size`, to which is appended a [`ThreadControlBlock`].
    ///
    /// The CpuLocalRegion uses `PT_TLS`'s `p_align` field passed in `block_align`
    /// to compute its layout and total size.
    ///
    /// ### Alignment
    ///
    /// ```text
    ///
    ///         V----------------------V  tls_align_up(tls_size_1, align_1)
    ///
    ///                                +-- gs:0
    ///                                |
    ///         +----------------------|-- tlsoffset_1 = gs:0 - tls_align_up(tls_size_1, align_1)
    ///         |                      |
    ///         V                      V
    ///
    ///         j----------------~-----j---------j
    ///    ...  |    tls_size_1  | pad |   TCB   |
    ///         j----------------~-----j---------j
    ///
    ///    ^    ^                      ^
    ///    |    |                      |
    ///    |    |                      +-- TCB_align: Determines alignment of everything.
    ///    |    |                          = max(align_of::<TCB>(), align_1). e.g. : 16.
    ///    |    |
    ///    |    +------------------------- TCB_align - n * align_1
    ///    |                               => still aligned to align_1 because TCB is aligned to align_1.
    ///    |
    ///    +------------------------------ alloc_align == TCB_align
    ///                                    => &TCB = &alloc + tls_align_up(gs:0 - tls_offset_1, TCB_align)
    ///
    ///    ^---^                           alloc_pad
    ///
    /// ```
    #[allow(clippy::cast_ptr_alignment)]
    fn allocate(block_src: &[u8], block_size: usize, block_align: usize) -> Self {
        let tls_offset1 = tls_align_up(block_size, block_align);
        let tcb_align = usize::max(align_of::<ThreadControlBlock>(), block_align);
        let tcb_offset = tls_align_up(tls_offset1, tcb_align);
        let alloc_pad_size = tcb_offset - tls_offset1;
        let layout = Layout::from_size_align(
            tcb_offset + size_of::<ThreadControlBlock>(),
            tcb_align
        ).unwrap();
        let alloc = unsafe {
            // safe: layout.size >= sizeof::<TCB> -> layout.size != 0
            alloc_zeroed(layout)
        };
        assert!(!alloc.is_null(), "cpu_locals: failed static area allocation");

        unsafe {
            // safe: everything is done within our allocation, u8 is always aligned.
            // copy data
            core::ptr::copy_nonoverlapping(
                block_src as *const [u8] as *const u8,
                alloc.add(alloc_pad_size),
                block_src.len()
            );
            // .tbss + pad are already set to 0 by alloc_zeroed.
            // write tcb
            core::ptr::write(
                alloc.add(tcb_offset) as *mut ThreadControlBlock,
                ThreadControlBlock {
                    tp_self_ptr: alloc.add(tcb_offset) as *const ThreadControlBlock
                }
            );
        };
        Self {
            ptr: alloc as usize,
            layout,
            tcb_offset
        }
    }
}

impl Drop for CpuLocalRegion {
    /// Dropping a CpuLocalRegion deallocates it.
    fn drop(&mut self) {
        unsafe {
            // safe: - self.ptr is obviously allocated.
            //       - self.layout is the same argument that was used for alloc.
            dealloc(self.ptr as *mut u8, self.layout)
        };
    }
}

impl Debug for CpuLocalRegion {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("CpuLocalRegion")
            .field("start_address", &self.ptr)
            .field("tcb_address", &self.tcb())
            .field("total_size", &self.layout.size())
            .finish()
    }
}
