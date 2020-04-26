//! Syscall implementations
//!
//! ![i can has cheezburger](https://raw.githubusercontent.com/sunriseos/SunriseOS/master/kernel/res/syscalls_doc.jpg)
//!
//! The syscall handlers of Sunrise.

use crate::i386;
use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::mem::{UserSpacePtr, UserSpacePtrMut};
use crate::paging::{MappingAccessRights, PAGE_SIZE};
use crate::paging::lands::{UserLand, VirtualSpaceLand};
use crate::frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait};
use crate::paging::mapping::MappingFrames;
use crate::process::{Handle, ThreadStruct, ProcessStruct};
use crate::event::{self, Waitable};
use crate::scheduler::{self, get_current_thread, get_current_process};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::ipc;
use crate::error::{UserspaceError, KernelError};
use crate::sync::SpinRwLock;
use crate::timer;
use failure::Backtrace;
use sunrise_libkern::{MemoryInfo, MemoryAttributes, MemoryPermissions, MemoryType, MemoryState};
use sunrise_libkern::process::*;
use bit_field::BitArray;
use crate::i386::gdt::{GDT, GdtIndex};
use core::convert::{TryFrom, TryInto};

/// Resize the heap of a process, just like a brk.
/// It can both expand, and shrink the heap.
///
/// If `new_size` == 0, the heap space is entirely de-allocated.
///
/// # Return
///
/// The address of the start of the heap.
///
/// # Error
///
/// * `new_size` must be [PAGE_SIZE] aligned.
///
/// [PAGE_SIZE]: crate::paging::PAGE_SIZE
pub fn set_heap_size(new_size: usize) -> Result<usize, UserspaceError> {
    let p = get_current_process();
    let mut pmemory = p.pmemory.lock();
    let heap_addr = pmemory.resize_heap(new_size)?;
    Ok(heap_addr.addr())
}

/// Maps the vga frame buffer mmio in userspace memory
pub fn map_framebuffer() -> Result<(usize, usize, usize, usize), UserspaceError> {
    let tag = i386::multiboot::get_boot_information().framebuffer_tag()
        .expect("Framebuffer to be provided");
    let framebuffer_size = tag.bpp as usize
                                * tag.width as usize
                                * tag.height as usize / 8;
    let frame_buffer_phys_region = unsafe {
        PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(tag.address as usize), framebuffer_size)?
    };

    let process = get_current_process();
    let mut memory = process.pmemory.lock();
    //let framebuffer_vaddr = memory.find_virtual_space::<UserLand>(frame_buffer_phys_region.size())?;
    // todo make user provide the address
    let framebuffer_vaddr = VirtualAddress(0x40000000);
    // Bleigh.
    memory.map_phys_region_to(frame_buffer_phys_region, framebuffer_vaddr, MemoryType::Normal, MappingAccessRights::u_rw())?;

    let addr = framebuffer_vaddr.0;
    let width = tag.width as usize;
    let height = tag.height as usize;
    let bpp = tag.bpp as usize;
    Ok((addr, width, height, bpp))
}

/// Create an event handle for the given IRQ number. Waiting on this handle will
/// wait until the IRQ is triggered. The flags argument configures the
/// triggering. If it is false, the IRQ is active HIGH level sensitive, if it is
/// true it is rising-edge sensitive.
///
/// # Return
///
/// A handle to the readable event associated with the IRQ.
///
/// # Error
///
/// NoSuchEntry: IRQ above 0x3FF or outside the IRQ access mask was given.
pub fn create_interrupt_event(irq_num: usize, _flag: u32) -> Result<usize, UserspaceError> {
    // TODO: Properly handle flags in create_interrupt_event.
    // BODY: The flags in create_interrupt_event configure the triggering of the
    // BODY: event. If it is false, the IRQ is active HIGH level sensitive. If it
    // BODY: is true, it is rising-edge sensitive.
    // TODO: Fully correct error handling in create_interrupt_event.
    // BODY: https://switchbrew.org/w/index.php?title=SVC#svcCreateInterruptEvent
    // BODY: contains complete error code information. Notably, we're missing the
    // BODY: IRQ already registered error, since our implementation allows
    // BODY: multiple InterruptEvent on the same IRQ.
    let curproc = scheduler::get_current_process();
    if !curproc.capabilities.irq_access_mask.get_bit(irq_num) {
        if cfg!(feature = "no-security-check") {
            error!("Process {} attempted to create unauthorized IRQEvent for irq {}", curproc.name, irq_num);
        } else {
            return Err(UserspaceError::NoSuchEntry);
        }
    }
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::InterruptEvent(event::wait_event(irq_num as u8))));
    Ok(hnd as _)
}

/// Gets the physical region a given virtual address maps.
///
/// This syscall is mostly used for DMAs, where the physical address of a buffer needs to be known
/// by userspace.
///
/// # Return
///
/// 0. The start address of the physical region.
/// 1. The start address of the virtual region.
/// 2. The length of the region.
///
/// # Error
///
/// - InvalidAddress: This address does not map physical memory.
pub fn query_physical_address(virtual_address: usize) -> Result<(usize, usize, usize), UserspaceError> {
    let virtual_address = VirtualAddress(virtual_address);
    let proc = scheduler::get_current_process();
    let mem = proc.pmemory.lock();
    let mapping = mem.query_memory(virtual_address);
    let keep_region;
    let frames = match mapping.mapping().frames() {
        MappingFrames::Owned(regions) => regions,
        MappingFrames::Shared(arc_regions) => { keep_region = arc_regions.read(); keep_region.as_ref() },
        MappingFrames::None =>
            return Err(KernelError::InvalidAddress { address: virtual_address.addr(), backtrace: Backtrace::new() }.into()),
    };

    let mut base_address = mapping.mapping().address();
    let mut virtual_offset = virtual_address.floor() - mapping.mapping().address();
    let mut mapping_length = mapping.mapping().length();
    let mut phys_offset = mapping.mapping().phys_offset();
    for region in frames {
        // Skip the frames that aren't part of the mapping.
        if region.size() <= phys_offset {
            phys_offset -= region.size();
            continue;
        }

        let mut region_physaddr = region.address();
        let mut region_size = region.size();
        region_physaddr += phys_offset;
        region_size -= phys_offset;
        phys_offset = 0;

        if virtual_offset < region_size {
            return Ok((region_physaddr.addr(), base_address.addr(), core::cmp::min(mapping_length, region_size)))
        } else {
            virtual_offset -= region_size;
            base_address += region_size;
            mapping_length -= region_size;
        }
    }
    unreachable!("Mapping is broken!");
}

/// Waits for one of the handles to signal an event.
///
/// When zero handles are passed, this will wait forever until either timeout or cancellation occurs.
///
/// If timeout is 0, the function will not schedule or register intent, but merely check if the handles are currently
/// signaled.
///
/// Does not accept 0xFFFF8001 or 0xFFFF8000 as handles.
///
/// # Result
///
/// Index of the handle that was signaled in the handles table.
///
/// # Error
///
/// - Timeout: the timeout was reached without a signal occuring on the given handles.
/// - InvalidHandle: A handle in the handle table does not exist.
pub fn wait_synchronization(handles_ptr: UserSpacePtr<[u32]>, timeout_ns: usize) -> Result<usize, UserspaceError> {
    // A list of underlying handles to wait for...
    let mut handle_arr = Vec::new();
    let proc = scheduler::get_current_process();
    {
        // Make sure we drop proclock before waiting.
        let handleslock = proc.phandles.lock();
        for handle in handles_ptr.iter() {
            let hnd = handleslock.get_handle(*handle)?;
            let _ = hnd.as_waitable()?;
            handle_arr.push(hnd);
        }
    }

    // Add a waitable for the timeout.
    let timeout_waitable = if timeout_ns != usize::max_value() && timeout_ns != 0 {
        Some(timer::wait_ns(timeout_ns as u64))
    } else {
        None
    };

    // Turn the handle array and the waitable timeout into an iterator of Waitables...
    let waitables = handle_arr.iter()
        .map(|v| v.as_waitable().unwrap())
        .chain(timeout_waitable.iter().map(|v| v as &dyn Waitable));

    // And now, wait!
    if timeout_ns == 0 {
        // Avoid rescheduling if we have a timeout of 0. We shouldn't even
        // register intent in this case!
        for (idx, item) in waitables.enumerate() {
            if item.is_signaled() {
                return Ok(idx)
            }
        }

        return Err(UserspaceError::Timeout);
    } else {
        let val = event::wait(waitables.clone())?;

        // Figure out which waitable got triggered.
        for (idx, handle) in waitables.enumerate() {
            if handle as *const _ == val as *const _ {
                if idx == handle_arr.len() {
                    return Err(UserspaceError::Timeout);
                } else {
                    return Ok(idx);
                }
            }
        }
    };
    // That's not supposed to happen. I heard that *sometimes*, dyn pointers will not turn up equal...
    unreachable!("No waitable triggered??!?");
}

/// Print the passed string to the serial port.
pub fn output_debug_string(msg: UserSpacePtr<[u8]>, level: usize, target: UserSpacePtr<[u8]>) -> Result<(), UserspaceError> {
    let level = match level {
        00..20    => log::Level::Error,
        20..40    => log::Level::Warn,
        40..60    => log::Level::Info,
        60..80    => log::Level::Debug,
        _         => log::Level::Trace,
    };

    log!(target: &*String::from_utf8_lossy(&*target), level, "{}", String::from_utf8_lossy(&*msg));
    Ok(())
}

/// Kills our own process.
pub fn exit_process() -> Result<(), UserspaceError> {
    ProcessStruct::kill_current_process();
    Ok(())
}

/// Connects to the given ClientPort.
///
/// # Returns
///
/// Returns a ClientSession handle.
///
/// # Error
///
/// - InvalidHandle: The passed handle does not exist, or is not a ClientPort.
/// - PortRemoteDead: All associated ServerPort handles are closed
pub fn connect_to_port(handle: u32) -> Result<usize, UserspaceError> {
    let curproc = scheduler::get_current_process();
    let clientport = curproc.phandles.lock().get_handle(handle)?.as_client_port()?;
    let clientsess = clientport.connect()?;
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(clientsess)));
    Ok(hnd as _)
}

/// Kills our own thread.
pub fn exit_thread() -> Result<(), UserspaceError> {
    ThreadStruct::exit(get_current_thread());
    Ok(())
}

/// Creates a thread in the current process.
/// The thread can then be started with the svcStartThread.
///
/// # Params
///
/// * `ip` the entry point of the thread,
/// * `arg` the initial argument of the thread (passed in eax),
/// * `sp` the top of the stack,
/// * `priority` ignored,
/// * `processor_id` ignored,
///
/// # Returns
///
/// A thread_handle to the created thread.
pub fn create_thread(ip: usize, arg: usize, sp: usize, _priority: u32, _processor_id: u32) -> Result<usize, UserspaceError> {
    let cur_proc = get_current_process();
    let thread = ThreadStruct::new(&cur_proc, VirtualAddress(ip), VirtualAddress(sp), Some(arg))?;
    let handle = Handle::Thread(thread);
    let mut handles_table = cur_proc.phandles.lock();
    Ok(handles_table.add_handle(Arc::new(handle)) as usize)
}

/// Starts a previously created thread.
///
/// # Error
///
/// * `InvalidHandle` if the handle is not a thread_handle,
/// * `InvalidState` if the thread has already started,
#[allow(clippy::unit_arg)]
pub fn start_thread(thread_handle: u32) -> Result<(), UserspaceError> {
    let cur_proc = get_current_process();
    let handles_table = cur_proc.phandles.lock();
    let thread = handles_table.get_handle(thread_handle)?.as_thread_handle()?;
    Ok(ThreadStruct::start(thread)?)
}

/// Connects to the given named port. The name should be a 12-byte array
/// containing a null-terminated string.
///
/// # Returns
///
/// Returns a ClientSession handle.
///
/// # Error
///
/// - ExceedingMaximum: Name is bigger than 12 character, or is missing a \0.
/// - NoSuchEntry: No named port were registered with this name.
/// - PortRemoteDead: All associated ServerPort handles are closed.
pub fn connect_to_named_port(name: UserSpacePtr<[u8; 12]>) -> Result<usize, UserspaceError> {
    let session = ipc::connect_to_named_port(*name)?;
    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(session)));
    Ok(hnd as _)
}

/// Creates a new ServerPort for the given named port. The name should be a
/// 12-byte array containing a null-terminated string. This ServerPort can be
/// connected to with `connect_to_named_port`.
///
/// # Returns
///
/// Returns a ServerSession handle.
///
/// # Error
///
/// - ExceedingMaximum: Name is bigger than 12 character, or is missing a \0.
pub fn manage_named_port(name_ptr: UserSpacePtr<[u8; 12]>, max_sessions: u32) -> Result<usize, UserspaceError> {
    let server = ipc::create_named_port(*name_ptr, max_sessions)?;
    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerPort(server)));
    Ok(hnd as _)
}

/// Waits for an incoming connection on the given ServerPort handle, and create
/// a new ServerSession for it.
///
/// # Returns
///
/// Returns a ServerSession handle.
///
/// # Error
///
/// - InvalidHandle: Handles does not exist or is not a ServerPort.
pub fn accept_session(porthandle: u32) -> Result<usize, UserspaceError> {
    let curproc = scheduler::get_current_process();
    let handle = curproc.phandles.lock().get_handle(porthandle)?;
    let port = match *handle {
        Handle::ServerPort(ref port) => port,
        _ => return Err(UserspaceError::InvalidHandle),
    };

    let server_session = port.accept()?;
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerSession(server_session)));
    Ok(hnd as _)
}

/// Send an IPC request through the ClientSession, and blocks until a response is
/// received. This variant takes a userspace buffer and size. Those must be
/// page-aligned.
///
/// # Error
///
/// - PortRemoteDead: All ServerSession associated with this handle are closed.
pub fn send_sync_request_with_user_buffer(buf: UserSpacePtrMut<[u8]>, handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    let sess = proc.phandles.lock().get_handle(handle)?.as_client_session()?;
    sess.send_request(buf)
}

/// If ReplyTarget is not zero, a reply from the given buffer will be sent to
/// that session. Then it will wait until either of the passed sessions has an
/// incoming message, is closed, a passed port has an incoming connection, or
/// the timeout expires. If there is an incoming message, it is copied to the
/// TLS.
///
/// If ReplyTarget is zero, the buffer should contain a blank message. If this
/// message has a C descriptor, the buffer it points to will be used as the
/// pointer buffer. See IPC_Marshalling#IPC_buffers. Note that a pointer buffer
/// cannot be specified if ReplyTarget is not zero.
///
/// After being validated, passed handles will be enumerated in order; even if a
/// session has been closed, if one that appears earlier in the list has an
/// incoming message, it will take priority and a result code of 0x0 will be
/// returned.
pub fn reply_and_receive_with_user_buffer(buf: UserSpacePtrMut<[u8]>, handles: UserSpacePtr<[u32]>, reply_target: u32, timeout: usize) -> Result<usize, UserspaceError> {
    let proc = scheduler::get_current_process();
    if reply_target != 0 {
        // get session
        let sess = proc.phandles.lock().get_handle(reply_target)?;
        sess.as_server_session()?.reply(UserSpacePtr(buf.0))?;
    }

    // TODO: Ensure all handles are ClientSessions
    let idx = wait_synchronization(handles, timeout)?;

    let servsess = proc.phandles.lock().get_handle(handles[idx])?.as_server_session()?;
    servsess.receive(buf, reply_target == 0)?;
    Ok(idx)
}

/// Closed the passed handle.
///
/// Does not accept 0xFFFF8001 or 0xFFFF8000 as handles.
pub fn close_handle(handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    proc.phandles.lock().delete_handle(handle)?;
    Ok(())
}

/// Sleep for a specified amount of time, or yield thread.
///
/// Setting nanoseconds to 0, -1, or -2 indicates a yielding type:
///
/// - 0 Yielding without core migration
/// - -1 Yielding with core migration
/// - -2 Yielding to any other thread
pub fn sleep_thread(nanos: usize) -> Result<(), UserspaceError> {
    if nanos == 0 {
        scheduler::schedule();
        Ok(())
    } else {
        event::wait(Some(&timer::wait_ns(nanos as u64) as &dyn Waitable)).map(|_| ())
    }
}

/// Sets the "signaled" state of an event. Calling this on an unsignalled event
/// will cause any thread waiting on this event through [wait_synchronization()]
/// to wake up. Any future calls to [wait_synchronization()] with this handle
/// will immediately return - the user has to clear the "signaled" state through
/// [clear_event()].
///
/// Takes either a [crate::event::ReadableEvent] or a
/// [crate::event::WritableEvent].
pub fn signal_event(handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    proc.phandles.lock().get_handle(handle)?.as_writable_event()?.signal();
    Ok(())
}

/// Clear the "signaled" state of an event. After calling this on a signaled
/// event, [wait_synchronization()] on this handle will wait until
/// [signal_event()] is called once again.
///
/// Calling this on a non-signaled event is a noop.
///
/// Takes either a [crate::event::ReadableEvent] or a
/// [crate::event::WritableEvent].
///
/// # Errors
///
/// - `InvalidState`
///   - The event wasn't signaled.
pub fn clear_event(handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    let handle = proc.phandles.lock().get_handle(handle)?;
    match &*handle {
        Handle::ReadableEvent(event) => event.clear_signal().map_err(|err| err.into()),
        Handle::WritableEvent(event) => event.clear_signal().map_err(|err| err.into()),
        _ => Err(UserspaceError::InvalidHandle)?
    }
}

/// Create a new Port pair. Those ports are linked to each-other: The server will
/// receive connections from the client.
pub fn create_port(max_sessions: u32, _is_light: bool, _name_ptr: UserSpacePtr<[u8; 12]>) -> Result<(usize, usize), UserspaceError>{
    let (server, client) = ipc::port::new(max_sessions);
    let curproc = scheduler::get_current_process();
    let serverhnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerPort(server)));
    let clienthnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientPort(client)));
    Ok((clienthnd as _, serverhnd as _))
}

/// Allocate a new SharedMemory region. This is a memory region backed by
/// DRAM allocated from the current process' pool partition, that can be mapped
/// in different processes.
///
/// Other perm can be used to enforce permission 1, 3, or 0x10000000 if don't
/// care.
pub fn create_shared_memory(size: u32, _myperm: u32, _otherperm: u32) -> Result<usize, UserspaceError> {
    let frames = FrameAllocator::allocate_frames_fragmented(size as usize)?;
    let handle = Arc::new(Handle::SharedMemory(Arc::new(SpinRwLock::new(frames))));
    let curproc = get_current_process();
    let hnd = curproc.phandles.lock().add_handle(handle);
    Ok(hnd as _)
}

/// Maps the block supplied by the handle. The required permissions are different
/// for the process that created the handle and all other processes.
///
/// Increases reference count for the SharedMemory object. Thus in order to
/// release the memory associated with the object, all handles to it must be
/// closed and all mappings must be unmapped.
pub fn map_shared_memory(handle: u32, addr: usize, size: usize, perm: u32) -> Result<(), UserspaceError> {
    let perm = MemoryPermissions::from_bits(perm).ok_or(UserspaceError::InvalidMemPerms)?;
    let curproc = get_current_process();
    let mem = curproc.phandles.lock().get_handle(handle)?.as_shared_memory()?;
    // TODO: RE the switch: can we map a subsection of a shared memory?
    if size != mem.read().iter().map(|v| v.size()).sum() {
        return Err(UserspaceError::InvalidSize)
    }
    curproc.pmemory.lock().map_partial_shared_mapping(mem, VirtualAddress(addr), 0, size, MemoryType::SharedMemory, perm.into())?;
    Ok(())
}

/// Unmaps this shared memory region. This cannot be used to partially unmap a
/// region: the address **must** be the start of the shared mapping, and the size
/// **must** be the full size of the mapping.
///
/// # Error
///
/// - InvalidAddress: address is not the start of a shared mapping
/// - InvalidSize: Size is not the same as the mapping size.
pub fn unmap_shared_memory(handle: u32, addr: usize, size: usize) -> Result<(), UserspaceError> {
    let curproc = get_current_process();
    let hmem = curproc.phandles.lock().get_handle(handle)?.as_shared_memory()?;
    let addr = VirtualAddress(addr);
    let mut memlock = curproc.pmemory.lock();
    {
        let qmem = memlock.query_memory(addr);
        let mapping = qmem.mapping();

        // Check that the given addr/size covers the full mapping.
        // TODO: Can we unmap a subsection of a shared memory?
        // BODY: I am unsure if it is allowed to unmap a subsection of a shared memory mapping.
        // This will require some reverse engineering work.
        if mapping.address() != addr {
            return Err(UserspaceError::InvalidAddress)
        }
        if mapping.length() != size {
            return Err(UserspaceError::InvalidSize)
        }

        // Check that we have the correct shared mapping.
        match (mapping.state().ty(), mapping.frames()) {
            (MemoryType::SharedMemory, MappingFrames::Shared(frames))
                if Arc::ptr_eq(frames, &hmem) => (),
            _ => return Err(UserspaceError::InvalidAddress)
        }
    }
    // We know that mapping = addr + size, and we know that handle == mapping.
    // Let's unmap.
    memlock.unmap(addr, size)?;
    Ok(())
}


/// Query information about an address. Will always fetch the lowest page-aligned
/// mapping that contains the provided address. Writes the output to the
/// given userspace pointer to a MemoryInfo structure.
#[inline(never)]
pub fn query_memory(mut meminfo: UserSpacePtrMut<MemoryInfo>, _unk: usize, addr: usize) -> Result<usize, UserspaceError> {
    let curproc = scheduler::get_current_process();
    let memlock = curproc.pmemory.lock();
    let qmem = memlock.query_memory(VirtualAddress(addr));
    let mapping = qmem.mapping();
    *meminfo = MemoryInfo {
        baseaddr: mapping.address().addr(),
        size: mapping.length(),
        memtype: mapping.state(),
        // TODO: Handle MemoryAttributes and refcounts in query_memory
        // BODY: QueryMemory gives userspace the ability to query if a memory
        // area is being used as an IPC buffer or a device address space. We
        // should implement this.
        memattr: MemoryAttributes::empty(),
        perms: mapping.flags().into(),
        ipc_ref_count: 0,
        device_ref_count: 0,
    };
    // TODO: PageInfo Handling
    // BODY: Properly return Page Information. The horizon/NX page-info stuff
    //       is not really documented yet, so this will require some RE work.
    Ok(0)
}

/// Create a new Session pair. Those sessions are linked to each-other: The
/// server will receive requests sent through the client.
///
/// # Returns
///
/// - A handle to a ServerSession
/// - A handle to a ClientSession
pub fn create_session(_is_light: bool, _unk: usize) -> Result<(usize, usize), UserspaceError> {
    let (server, client) = ipc::session::new();
    let curproc = scheduler::get_current_process();
    let serverhnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerSession(server)));
    let clienthnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(client)));
    Ok((serverhnd as _, clienthnd as _))
}

/// Create a [WritableEvent]/[ReadableEvent] pair. Signals on the
/// [WritableEvent] will cause threads waiting on the [ReadableEvent] to wake
/// up until the signal is cleared/reset.
///
/// [ReadableEvent]: crate::event::ReadableEvent
/// [WritableEvent]: crate::event::WritableEvent
pub fn create_event() -> Result<(usize, usize), UserspaceError> {
    let (writable, readable) = crate::event::new_pair();
    let curproc = scheduler::get_current_process();
    let mut phandles = curproc.phandles.lock();
    let readable = phandles.add_handle(Arc::new(Handle::ReadableEvent(readable)));
    let writable = phandles.add_handle(Arc::new(Handle::WritableEvent(writable)));
    Ok((usize::try_from(writable).unwrap(), usize::try_from(readable).unwrap()))
}

/// Maps a physical region in the address space of the process.
///
/// # Returns
///
/// The virtual address where it was mapped.
///
/// # Errors
///
/// * InvalidAddress:
///     * `virtual_address` is already occupied.
///     * `virtual_address` is not PAGE_SIZE aligned.
///     * `physical_address` points to a physical region in DRAM (it's not MMIO).
/// * InvalidLength:
///     * `length` is not PAGE_SIZE aligned.
///     * `length` is zero.
pub fn map_mmio_region(physical_address: usize, size: usize, virtual_address: usize, writable: bool) -> Result<(), UserspaceError> {
    let region = unsafe { PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(physical_address), size)? };
    let curproc = scheduler::get_current_process();
    let mut mem = curproc.pmemory.lock();
    mem.map_phys_region_to(region, VirtualAddress(virtual_address), MemoryType::Io, if writable { MappingAccessRights::u_rw() } else { MappingAccessRights::u_r() })?;
    Ok(())
}

/// Set thread local area pointer.
///
/// Akin to `set_thread_area` on Linux, this syscall sets the `gs` segment selector's base address
/// to the address passed as argument.
///
/// The user will likely want to make it point to its elf thread local storage, as `gs:0` is expected
/// to contain the thread pointer `tp`.
///
/// Unlike linux, you only have **one** user controlled segment, found in `gs`, and you can only set its address.
///
/// The limit will always be set to `0xFFFFFFFF`, and adding this offset to a non-zero base address
/// means that the resulting address will "wrap around" the address space, and end-up **under**
/// the base address.
/// You can use this property to implement thread local storage variant II - gnu model,
/// as thread local variable are expected to be found "below" `gs:0`, with "negative" offset such as
/// `gs:0xFFFFFFFC`.
///
/// ## x86_64
///
/// ![same, but different, but still same](https://media.giphy.com/media/C6JQPEUsZUyVq/giphy.gif)
///
/// `fs` is used instead of `gs`, because reasons.
///
/// # Errors
///
/// * The whole initial design of TLS on x86 should be considered an error.
/// * No returned error otherwise.
pub fn set_thread_area(segment_base_address: usize) -> Result<(), UserspaceError> {
    let segment_base_address = VirtualAddress(segment_base_address);
    let mut gdt = GDT.r#try().expect("GDT not initialized").lock();
    gdt.table[GdtIndex::UTlsElf as usize].set_base(segment_base_address.addr() as u32);
    gdt.commit(None, None, None, None, None, None);
    // store it in the thread struct.
    let thread = get_current_thread();
    *thread.tls_elf.lock() = segment_base_address;
    Ok(())
}

/// Change permission of a page-aligned memory region. Acceptable permissions
/// are ---, r-- and rw-. In other words, it is not allowed to set the
/// executable bit, nor is it acceptable to use write-only permissions.
///
/// This can only be used on memory regions with the
/// [`process_permission_change_allowed`] state.
///
/// # Errors
///
/// - `InvalidAddress`
///   - Supplied address is not page-aligned.
/// - `InvalidSize`
///    - Supplied size is zero or not page-aligned.
/// - `InvalidMemState`
///    - Supplied memory range is not contained within the target process
///      address space.
///    - Supplied memory range does not have the [`process_permission_change_allowed`]
///      state.
///
/// [`process_permission_change_allowed`]: sunrise_libkern::MemoryState::PROCESS_PERMISSION_CHANGE_ALLOWED
pub fn set_process_memory_permission(proc_hnd: u32, addr: usize, size: usize, perms: u32) -> Result<(), UserspaceError> {
    let addr = VirtualAddress(addr);

    addr.check_aligned_to(PAGE_SIZE)?;
    if size == 0 || size & (PAGE_SIZE - 1) != 0 {
        return Err(UserspaceError::InvalidSize);
    }

    if addr.checked_add(size).is_none() {
        return Err(UserspaceError::InvalidMemState);
    }

    let perms = MemoryPermissions::from_bits(perms).ok_or(UserspaceError::InvalidMemPerms)?;
    perms.check()?;

    let dstproc = scheduler::get_current_process().phandles.lock().get_handle(proc_hnd)?.as_process()?;
    // Use dstproc.addrSpace
    if !UserLand::contains_region(addr, size) {
        return Err(UserspaceError::InvalidMemState);
    }

    // # KMemoryManager::SetProcessMemoryPermission

    let mut size = size;
    let mut addr = addr;

    let mut dstmem = dstproc.pmemory.lock();

    dstmem.check_range(addr, size,
        MemoryState::PROCESS_PERMISSION_CHANGE_ALLOWED, MemoryState::PROCESS_PERMISSION_CHANGE_ALLOWED,
        MemoryPermissions::empty(), MemoryPermissions::empty(),
        MemoryAttributes::all(), MemoryAttributes::empty(),
        MemoryAttributes::IPC_MAPPED | MemoryAttributes::DEVICE_MAPPED)?;

    while size != 0 {
        let meminfo = dstmem.query_memory(addr);

        let mapping_addr = meminfo.mapping().address();
        let mapping_length = meminfo.mapping().length();
        core::mem::drop(meminfo);
        let meminfo = dstmem.unmap(mapping_addr, mapping_length).expect("Unmap can't fail.");

        let frames = if let MappingFrames::Shared(frames) = meminfo.frames() {
            frames
        } else {
            panic!("Non-shared frames in mapping {:?}", meminfo);
        };

        // Split mapping
        if meminfo.address() < addr {
            dstmem.map_partial_shared_mapping(frames.clone(), meminfo.address(), meminfo.phys_offset(), addr - meminfo.address(), meminfo.state().ty(), meminfo.flags()).expect("Can't fail");
        }
        if meminfo.address() + meminfo.length() > addr + size {
            let phys_offset = meminfo.phys_offset() + addr + size - meminfo.address();
            dstmem.map_partial_shared_mapping(frames.clone(), addr + size, phys_offset, (meminfo.address() + meminfo.length()) - (addr + size), meminfo.state().ty(), meminfo.flags()).expect("Can't fail");
        }

        // Handle middle mapping.
        let offset_in_mapping = addr - meminfo.address();
        let offset = offset_in_mapping + meminfo.phys_offset();
        let curlen = core::cmp::min(size, meminfo.length() - offset_in_mapping);

        let out_type = match meminfo.state().ty() {
            MemoryType::CodeStatic => if perms.contains(MemoryPermissions::WRITABLE) { MemoryType::CodeMutable } else { MemoryType::CodeStatic },
            MemoryType::ModuleCodeStatic => if perms.contains(MemoryPermissions::WRITABLE) { MemoryType::ModuleCodeMutable } else { MemoryType::ModuleCodeStatic },
            _ => unreachable!("Got a state PROCESS_PERMISSION_CHANGE_ALLOWED that wasn't CodeStatic or ModuleCodeStatic, but a {:?}", meminfo.state().ty())
        };

        dstmem.map_partial_shared_mapping(frames.clone(), addr, offset, curlen, out_type, perms.into())?;

        size -= curlen;
        addr += curlen;
    }

    Ok(())
}

/// Maps the given src memory range from a remote process into the current
/// process as RW-. This is used by the Loader to load binaries into the memory
/// region allocated by the kernel in [create_process()].
///
/// The src region should have the MAP_PROCESS state, which is only available on
/// CodeStatic/CodeMutable and ModuleCodeStatic/ModuleCodeMutable.
///
/// # Errors
///
/// - `InvalidAddress`
///    - src_addr or dst_addr is not aligned to 0x1000.
/// - `InvalidSize`
///    - size is 0
///    - size is not aligned to 0x1000.
/// - `InvalidMemState`
///    - `src_addr + size` overflows
///    - `dst_addr + size` overflows
///    - The src region is outside of the UserLand address space.
///    - The dst region is outside of the UserLand address space, or within the
///      heap or map memory region.
///    - The src memory pages does not have the MAP_PROCESS state.
///    - The dst memory pages is not of the Unmapped type.
/// - `InvalidHandle`
///    - The handle passed as an argument does not exist or is not a Process
///      handle.
pub fn map_process_memory(dst_addr: usize, proc_hnd: u32, src_addr: usize, size: usize) -> Result<(), UserspaceError> {
    let dst_addr = VirtualAddress(dst_addr);
    let src_addr = VirtualAddress(src_addr);

    src_addr.check_aligned_to(PAGE_SIZE)?;
    dst_addr.check_aligned_to(PAGE_SIZE)?;

    if size == 0 || size & (PAGE_SIZE - 1) != 0 {
        return Err(UserspaceError::InvalidSize);
    }

    if src_addr.checked_add(size).is_none() {
        return Err(UserspaceError::InvalidMemState);
    }
    if dst_addr.checked_add(size).is_none() {
        return Err(UserspaceError::InvalidMemState);
    }

    let curproc = scheduler::get_current_process();
    let srcproc = curproc.phandles.lock().get_handle(proc_hnd)?.as_process()?;

    // check srcproc address space
    if !UserLand::contains_region(src_addr, size) {
        return Err(UserspaceError::InvalidMemState);
    }

    // If dst_addr is within Heap region or Map region, error out.
    if !UserLand::contains_region(dst_addr, size) {
        return Err(UserspaceError::InvalidMemRange)
    }

    let mut size = size;
    let mut src_addr = src_addr;
    let mut dst_addr = dst_addr;

    let srcmem = srcproc.pmemory.lock();
    let mut dstmem = curproc.pmemory.lock();

    // Check we're allowed to MAP_PROCESS in the source.
    srcmem.check_range(src_addr, size,
        MemoryState::MAP_PROCESS_ALLOWED, MemoryState::MAP_PROCESS_ALLOWED,
        MemoryPermissions::empty(), MemoryPermissions::empty(),
        MemoryAttributes::all(), MemoryAttributes::empty(),
        MemoryAttributes::IPC_MAPPED | MemoryAttributes::DEVICE_MAPPED)?;

    // Check the destination is fully unmapped.
    dstmem.check_range(dst_addr, size,
        MemoryState::all(), MemoryType::Unmapped.get_memory_state(),
        MemoryPermissions::empty(), MemoryPermissions::empty(),
        MemoryAttributes::empty(), MemoryAttributes::empty(),
        MemoryAttributes::empty())?;

    while size != 0 {
        let meminfo = srcmem.query_memory(src_addr);

        let offset_in_mapping = src_addr - meminfo.mapping().address();
        let offset = offset_in_mapping + meminfo.mapping().phys_offset();
        let curlen = core::cmp::min(size, meminfo.mapping().length() - offset_in_mapping);
        if let MappingFrames::Shared(frames) = meminfo.mapping().frames() {
            dstmem.map_partial_shared_mapping(frames.clone(), dst_addr, offset, curlen,
                MemoryType::ProcessMemory, MappingAccessRights::u_rw())
                .unwrap_or_else(|err| panic!("Failed to map in dst mem: {:?}", err));
        } else {
            panic!("Got a broken meminfo with non-arc'd frames: {:?}", meminfo);
        }
        size -= curlen;
        src_addr += curlen;
        dst_addr += curlen;
    }

    Ok(())
}

/// Unmaps a memory range mapped with [map_process_memory()]. `dst_addr` is an
/// address in the current address space, while `src_addr` is the address in the
/// remote address space that was previously mapped.
///
/// It is possible to partially unmap a ProcessMemory.
///
/// # Errors
///
/// - `InvalidAddress`
///    - src_addr or dst_addr is not aligned to 0x1000.
/// - `InvalidSize`
///    - size is 0
///    - size is not aligned to 0x1000.
/// - `InvalidMemState`
///    - `src_addr + size` overflows
///    - `dst_addr + size` overflows
///    - The src region is outside of the UserLand address space.
///    - The dst region is outside of the UserLand address space, or within the
///      heap or map memory region.
///    - The src memory pages does not have the MAP_PROCESS state.
///    - The src memory pages is not of the ProcessMemory type.
/// - `InvalidMemRange`
///    - The given source range does not map the same pages as the given dst
///      range.
/// - `InvalidHandle`
///    - The handle passed as an argument does not exist or is not a Process
///      handle.
pub fn unmap_process_memory(dst_addr: usize, proc_hnd: u32, src_addr: usize, size: usize) -> Result<(), UserspaceError> {
    let src_addr = VirtualAddress(src_addr);
    let dst_addr = VirtualAddress(dst_addr);

    src_addr.check_aligned_to(PAGE_SIZE)?;
    dst_addr.check_aligned_to(PAGE_SIZE)?;

    if size == 0 || size & (PAGE_SIZE - 1) != 0 {
        return Err(UserspaceError::InvalidSize);
    }

    if src_addr.checked_add(size).is_none() {
        return Err(UserspaceError::InvalidMemState);
    }
    if dst_addr.checked_add(size).is_none() {
        return Err(UserspaceError::InvalidMemState);
    }

    let curproc = scheduler::get_current_process();
    let srcproc = curproc.phandles.lock().get_handle(proc_hnd)?.as_process()?;

    // check srcproc address space
    if !UserLand::contains_region(src_addr, size) {
        return Err(UserspaceError::InvalidMemState);
    }

    // If dst_addr is within Heap region or Map region, error out.
    if !UserLand::contains_region(dst_addr, size) {
        return Err(UserspaceError::InvalidMemRange)
    }

    let mut size = size;
    let mut src_addr = src_addr;
    let mut dst_addr = dst_addr;

    let srcmem = srcproc.pmemory.lock();
    let mut dstmem = curproc.pmemory.lock();

    // Check we're allowed to MAP_PROCESS in the source.
    srcmem.check_range(src_addr, size,
        MemoryState::MAP_PROCESS_ALLOWED, MemoryState::MAP_PROCESS_ALLOWED,
        MemoryPermissions::empty(), MemoryPermissions::empty(),
        MemoryAttributes::all(), MemoryAttributes::empty(),
        MemoryAttributes::IPC_MAPPED | MemoryAttributes::DEVICE_MAPPED)?;

    // Check the destination is all ProcessMemory.
    dstmem.check_range(dst_addr, size,
        MemoryState::all(), MemoryType::ProcessMemory.get_memory_state(),
        MemoryPermissions::empty(), MemoryPermissions::empty(),
        MemoryAttributes::all(), MemoryAttributes::empty(),
        MemoryAttributes::empty())?;

    // TODO: UnmapProcessMemory: Verify that the src page list == dst page list.
    // BODY: In UnmapProcessMemory, we don't ensure that src_address is correct,
    // BODY: that is, we don't check that the frames in the dst match the frame
    // BODY: in the src. HOS/NX does this by building a PageList (essentially
    // BODY: a vector of frames) and comparing them.
    // BODY:
    // BODY: We could do something similar by iterating over the Mappings and
    // BODY: checking if their Frames + PhysOffset are equals.

    // Unmap.
    while size != 0 {
        let mapping_address;
        let mapping_length;

        {
            let meminfo = dstmem.query_memory(dst_addr);
            mapping_address = meminfo.mapping().address();
            mapping_length = meminfo.mapping().length();
        }

        let mapping = dstmem.unmap(mapping_address, mapping_length).unwrap();
        let offset_in_mapping = dst_addr - mapping.address();
        let curlen = core::cmp::min(size, mapping.length() - offset_in_mapping);

        if let MappingFrames::Shared(frames) = mapping.frames() {

            // Remap left bit
            if offset_in_mapping != 0 {
                dstmem.map_partial_shared_mapping(frames.clone(), mapping.address(),
                    mapping.phys_offset(), offset_in_mapping, mapping.state().ty(),
                    mapping.flags()).unwrap();
            }

            // Remap right bit
            if curlen != mapping.length() - offset_in_mapping {
                dstmem.map_partial_shared_mapping(frames.clone(),
                    mapping.address() + offset_in_mapping + size,
                    mapping.phys_offset() + offset_in_mapping + size,
                    mapping.length() - (offset_in_mapping + size),
                    mapping.state().ty(),
                    mapping.flags()).unwrap();
            }
        } else {
            panic!("Got a broken meminfo with non-arc'd frames: {:?}", mapping);
        }
        size -= curlen;
        src_addr += curlen;
        dst_addr += curlen;
    }

    Ok(())
}

/// Creates a new process. This will create an empty address space without any
/// thread yet. The size of this address space is controlled through
/// the [ProcInfoAddrSpace] found in `procinfo`.
///
/// It will create an empty memory region at `code_addr` spanning
/// `code_num_pages` pages. This region will initially not have any user
/// permissions - the user is expected to call set_process_memory_permissions.
///
/// The code region needs to fall within a region called the code allowed
/// region, which depends on the address space:
///
/// For 32-bit address space: 0x00200000-0x003FFFFFFF
///
/// For 36-bit address space: 0x08000000-0x007FFFFFFF
///
/// For 39-bit address space: 0x08000000-0x7FFFFFFFFF
///
/// # Errors
///
/// * `InvalidEnum`
///    * ProcInfo contains invalid bitfields
/// * `InvalidAddress`
///    * ProcInfo's `code_addr` is not 21-bit aligned.
/// * `InvalidMemRange`
///    * ProcInfo's `code_addr` is not within the allowed code region.
/// * All the errors from [crate::process::capabilities::ProcessCapabilities#parse_kacs]
pub fn create_process(procinfo: UserSpacePtr<ProcInfo>, caps: UserSpacePtr<[u8]>) -> Result<usize, UserspaceError> {
    // Ensure the procinfo structure is well-formed.
    procinfo.flags.check()?;

    let code_allowed_region = match procinfo.flags.address_space_type() {
        ProcInfoAddrSpace::AS32BitNoMap |
        ProcInfoAddrSpace::AS32Bit => 0x00200000..=0x003FFFFFFF,
        ProcInfoAddrSpace::AS36Bit => 0x08000000..=0x007FFFFFFF,
        ProcInfoAddrSpace::AS39Bit => 0x08000000..=0x7FFFFFFFFF
    };

    // The code address must be aligned with 21 bit.
    if procinfo.code_addr & ((1 << 21) - 1) != 0 {
        return Err(UserspaceError::InvalidAddress);
    }

    // Check code_num_pages < 0 => InvalidSize. Our code_num_pages is unsigned,
    // we don't need to do this.

    // Check personalMmHeapNumPages < 0 => InvalidSize. Again, unsigned.
    // Check !((code_num_pages | personal_mm_heap_num_pages) & 0xFFF0000000000000) => InvalidSize.
    // Check code_num_pages + personal_mm_heap_num_pages overflows => MemoryExhaustion
    // Check !((code_num_pages + personal_mm_heap_num_pages) & 0xFFF0000000000000) => InvalidSize.
    // No clue what these checks are for.

    // Check that our region is contained in the code_allowed_region.
    if !(code_allowed_region.contains(&procinfo.code_addr) &&
        code_allowed_region.contains(&(procinfo.code_addr + (u64::from(procinfo.code_num_pages) * PAGE_SIZE as u64))))
    {
        return Err(UserspaceError::InvalidMemRange)
    }

    // Check (code_num_pages | personal_mm_heap_num_pages) >> 21 => MemoryExhaustion
    // Check (code_num_pages + personal_mm_heap_num_pages) >> 21 => MemoryExhaustion

    let newproc = ProcessStruct::new(&procinfo, Some(&caps[..]))?;

    // Enter KProcess::CreateFromUserData

    // TODO: Create memory region reservations
    // BODY: Memory region reservations is sort of insane in HOS/NX - especially
    // BODY: for 32-bit. I'll figure it out later.

    newproc.pmemory.lock().create_regular_mapping(VirtualAddress(procinfo.code_addr as usize), procinfo.code_num_pages as usize * PAGE_SIZE, MemoryType::CodeStatic, MappingAccessRights::k_r())?;

    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::Process(newproc)));
    Ok(hnd as _)
}

/// Start the given process on the provided CPU with the provided scheduler
/// priority.
///
/// A stack of the given size will be allocated using the process' memory
/// resource limit and memory pool.
///
/// The entrypoint is assumed to be the first address of the `code_addr` region
/// provided in [create_process()]. It takes two parameters: the first is the
/// usermode exception handling context, and should always be NULL. The second
/// is a handle to the main thread.
///
/// # Errors
///
/// - `InvalidProcessorId`
///   - Attempted to start the process on a processor that doesn't exist on the
///     current machine, or a processor that the process is not allowed to use.
/// - `InvalidThreadPriority`
///   - Attempted to use a priority above 0x3F, or a priority that the created
///     process is not allowed to use.
/// - `MemoryFull`
///   - Provided stack size is bigger than available vmem space.
pub fn start_process(hnd: u32, main_thread_prio: u32, default_cpuid: u32, main_thread_stacksz: usize) -> Result<(), UserspaceError> {
    let target_proc = scheduler::get_current_process().phandles.lock().get_handle(hnd)?.as_process()?;

    // Check max CPU ID
    // || !target_proc.capabilities.allowed_cpu_id_bitmask.get_bit(default_cpuid)
    if default_cpuid > 1 {
        return Err(UserspaceError::InvalidProcessorId)
    }

    // || !target_proc.capabilities.allowed_thread_prio_bit_mask.get_bit(main_thread_prio)
    if main_thread_prio > 0x3F {
        return Err(UserspaceError::InvalidThreadPriority)
    }

    // Set process default cpu core.

    ProcessStruct::start(&target_proc, main_thread_prio, main_thread_stacksz)?;
    Ok(())
}

/// Extract information from a process.
///
/// Info Type        | Description
/// -----------------|--------------------------
/// ProcessState = 0 | The state the current process is in. Returns an instance
///                  | of [sunrise_libkern::process::ProcessState].
///
/// # Errors
///
/// - `InvalidHandle`
///   - The passed handle is invalid or not a process.
/// - `InvalidEnum`
///   - The passed info_type is unknown.
pub fn get_process_info(hnd: u32, info_type: u32) -> Result<usize, UserspaceError> {
    let info_type = ProcessInfoType(info_type);
    let target_proc = scheduler::get_current_process().phandles.lock().get_handle(hnd)?.as_process()?;

    match info_type {
        ProcessInfoType::ProcessState => Ok(target_proc.state().0 as usize),
        _ => Err(UserspaceError::InvalidEnum)
    }
}

/// Clear the "signaled" state of a readable event or process. After calling
/// this on a signaled event, [wait_synchronization()] on this handle will wait
/// until the handle is signaled again.
///
/// Takes either a `ReadableEvent` or a `Process`.
///
/// Note that once a Process enters the Exited state, it is permanently signaled
/// and cannot be reset. Calling ResetSignal will return an InvalidState error.
///
/// # Errors
///
/// - `InvalidState`
///   - The event wasn't signaled.
///   - The process was in Exited state.
pub fn reset_signal(hnd: u32) -> Result<(), UserspaceError> {
    let hnd = scheduler::get_current_process().phandles.lock().get_handle(hnd)?;

    match &*hnd {
        Handle::Process(process) =>
            process.clear_signal().map_err(|err| err.into()),
        Handle::ReadableEvent(revent) =>
            revent.clear_signal().map_err(|err| err.into()),
        _ => Err(UserspaceError::InvalidHandle)
    }
}

/// Gets the PID of the given Process handle. Alias handles (0xFFFF8000 and
/// 0xFFFF8001) are not allowed here. PIDs are global, unique identifiers for a
/// given process. PIDs are never reused, and can be passed over IPC safely (the
/// kernel ensures the correct pid is passed when a process does a request),
/// making them the best way for sysmodule to identify a calling process.
///
/// # Errors
///
/// - `InvalidHandle`
///   - The given handle is invalid or not a process.
pub fn get_process_id(hnd: u32) -> Result<usize, UserspaceError> {
    let process = scheduler::get_current_process().phandles.lock()
        .get_handle_no_alias(hnd)?.as_process()?;

    Ok(process.pid)
}

/// Kills the given process, terminating the execution of all of its thread and
/// putting its state to Exiting/Exited.
///
/// Returns an error if used on a process that wasn't started.
///
/// # Errors
///
/// - `InvalidState`
///   - The process wasn't started (it is in Created or CreatedAttached state).
/// - `InvalidHandle`
///   - The given handle is invalid or not a process.
pub fn terminate_process(hnd: u32) -> Result<(), UserspaceError> {
    let process = scheduler::get_current_process().phandles.lock()
        .get_handle(hnd)?.as_process()?;

    if Arc::ptr_eq(&scheduler::get_current_process(), &process) {
        ProcessStruct::kill_current_process();
    }

    process.terminate()?;
    Ok(())
}

/// Fills the provided array with the pids of currently living processes. A
/// process "lives" so long as it is currently running or a handle to it still
/// exists.
///
/// It returns the total number of processes currently alive. If this number is
/// bigger than the size of PidBuffer, the user won't have all the pids.
pub fn get_process_list(out_pids: u64, max_pids: u64) -> Result<usize, UserspaceError> {
    // The official code goes through the KProcess slab, iterating over the live
    // object pool.
    //
    // We don't have a slab allocator or anything else, so we have a separate
    // array for this.

    let process_list = crate::process::PROCESS_LIST.lock();
    let iter = process_list.iter()
        .take(max_pids.try_into().unwrap_or(usize::max_value()))
        .enumerate();
    let out_len = iter.len();
    for (idx, item) in iter {
        if let Some(item) = item.upgrade() {
            unsafe {
                *UserSpacePtrMut((out_pids as *mut u64).add(idx)) = item.pid as u64;
            }
        }
    }
    Ok(out_len)
}