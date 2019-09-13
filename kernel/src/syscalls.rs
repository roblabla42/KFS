//! Syscall implementations
//!
//! ![i can has cheezburger](https://raw.githubusercontent.com/sunriseos/SunriseOS/master/kernel/res/syscalls_doc.jpg)
//!
//! The syscall handlers of Sunrise.

use crate::i386;
use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::mem::{UserSpacePtr, UserSpacePtrMut};
use crate::paging::MappingAccessRights;
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
use sunrise_libkern::{MemoryInfo, MemoryAttributes, MemoryPermissions, MemoryType};
use bit_field::BitArray;
use crate::i386::gdt::{GDT, GdtIndex};
use core::convert::TryFrom;

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
        PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(tag.address), framebuffer_size)?
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
/// 1. 0x00000000 (On Horizon it contains the KernelSpace virtual address of this mapping,
///    but I don't see any use for it).
/// 2. The length of the physical region.
// sunrise extension
/// 3. The offset in the region of the given virtual address.
///
/// # Error
///
/// - InvalidAddress: This address does not map physical memory.
// TODO: Kernel mappings must be physically continuous.
// BODY: Virtual memory is a great thing, it can make a fragmented mapping appear contiguous from the
// BODY: userspace. But unfortunately Horizon does not take advantage of this feature, and
// BODY: allocates its mapping as a single Physical Memory Region.
// BODY:
// BODY: Its syscalls are based around that fact, and to do a `virt_to_phys(addr)`, you simply
// BODY: need to `query_memory(addr).offset` to get its offset in its mapping, and compute its
// BODY: physical address as `query_physical_address(addr).base + offset`.
// BODY:
// BODY: This will not work when the mapping is composed of several physical regions, and
// BODY: Horizon drivers will not be expecting that. So for them to work on our kernel, we must
// BODY: renounce using fragmented mappings.
// BODY:
// BODY: For now `query_physical_address` is providing an additional "offset in physical region" return value,
// BODY: to help KFS drivers doing a virt_to_phys without needing to walk the list of physical regions.
pub fn query_physical_address(virtual_address: usize) -> Result<(usize, usize, usize, usize), UserspaceError> {
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
    let offset = virtual_address - mapping.mapping().address() + mapping.mapping().phys_offset();
    let mut i = 0;
    let pos = frames.iter().position(|region| { i += region.size(); i > offset })
        .expect("Mapping region count is corrupted");
    Ok((frames[pos].address().addr(), 0x00000000, frames[pos].size(), offset - (i - frames[pos].size())))
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
        Some(timer::wait_ns(timeout_ns))
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
    ProcessStruct::kill_process(get_current_process());
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
    ThreadStruct::kill(get_current_thread());
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
/// * `ProcessAlreadyStarted` if the thread has already started,
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
        event::wait(Some(&timer::wait_ns(nanos) as &dyn Waitable)).map(|_| ())
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
pub fn clear_event(handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    let handle = proc.phandles.lock().get_handle(handle)?;
    match &*handle {
        Handle::ReadableEvent(event) => event.clear_signal(),
        Handle::WritableEvent(event) => event.clear_signal(),
        _ => Err(UserspaceError::InvalidHandle)?
    }
    Ok(())
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
