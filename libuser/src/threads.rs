//! Low-level api to create threads and start them.
//!
//! This module defines the low-level representation of a thread, kind to pthread on Unix.
//! You will want to abstract it in the libstd.
//!
//! # Threads on SunriseOS
//!
//! The sunrise kernel provides only three syscalls of interest relative to threads:
//!
//! * [`svcCreateThread`] : allocates kernel resources for a thread and returns a handle to it.
//! * [`svcStartThread`] : starts a thread created by `svcCreateThread`.
//! * [`svcExitThread`] : terminates the current thread.
//!
//! Note that it is impossible to terminate another thread but our own.
//!
//! The first thread of a process (referred later in this doc as "main thread") gets the handle to
//! its own thread in one of its registers when it is started by the kernel.
//!
//! ### TLS region
//!
//! Every thread possesses a small memory region called [Thread Local Storage region] which the kernel
//! allocates, and puts its address in a ro register so it can be accessed from the userspace.
//!
//! There lives the [IpcBuffer], and a userspace controlled pointer where the user can store a
//! user-defined context. We use it to to keep a pointer to a [ThreadContext] (see below).
//!
//! # Threads in libuser
//!
//! The main thread will always live for the entire life of the process.
//! When its routine returns, it calls `svcExitProcess` and every other thread will be killed.
//!
//! It can create other threads, which are represented by the [`Thread`] struct.
//! A `Thread` detaches (read "leak") the associated thread when it is dropped,
//! which means that there is no longer any handle to thread and no way to join on it.
//!
//! This is analog to the way the libstd threads work.
//!
//! ### Thread context
//!
//! For every thread we create (and also for the main thread), we allocate a [ThreadContext]
//! structure on the heap, which holds its stack, its thread handle so it will be able to use
//! mutexes, the routine we want it to execute, and the argument to pass to it.
//!
//! ### Thread entry point
//!
//! We tell the kernel the entry of the thread is [`thread_trampoline`].
//! This function will set-up a valid environment for the routine (mainly handle ELF thread local variables),
//! call the routine with its argument, and finally call `svcExitThread` when the routine has returned.
//!
//! [`svcCreateThread`]: crate::syscalls::create_thread
//! [`svcStartThread`]: crate::syscalls::start_thread
//! [`svcExitThread`]: crate::syscalls::exit_thread
//! [Thread Local Storage region]: sunrise_libkern::TLS
//! [IpcBuffer]: sunrise_libkern::IpcBuffer
//! [ThreadContext]: ThreadContext
//! [`Thread`]: Thread
//! [`thread_trampoline`]: thread_trampoline

use crate::types::{Thread as ThreadHandle};

#[cfg(not(feature = "build-for-std-app"))]
use crate::types::Handle;

use crate::syscalls;
use crate::error::Error;
use crate::error::KernelError;
use crate::thread_local_storage::TlsElf;
use sunrise_libkern::{TLS, IpcBuffer};
use alloc::boxed::Box;
use alloc::alloc::{alloc, dealloc, Layout};
use core::mem::ManuallyDrop;
use core::fmt;
use spin::Once;

/// Default size of a thread's stack, in bytes.
pub const DEFAULT_STACK_SIZE: usize = 0x8000;

/// Stack allocation informations
#[derive(Debug)]
struct StackContext {
    /// The addresss of the allocated stack
    stack_address: *const u8,

    /// The stack layout.
    stack_layout: Layout
}

impl StackContext {
    /// Create a new StackContext from a given size. The stack size must be bigger than 0.
    ///
    /// # Errors
    ///
    /// - `InvalidSize`
    ///   - The size passed was 0
    ///   - The size overflows when rounded up to the nearest multiple of PAGE_SIZE.
    pub fn new(stack_size: usize) -> Result<Self, Error> {
        if stack_size == 0 {
            return Err(KernelError::InvalidSize.into());
        }

        let stack_layout = Layout::from_size_align(stack_size, crate::mem::PAGE_SIZE)
            .or(Err(KernelError::InvalidSize))?;

        Ok(StackContext {
            stack_address: unsafe {
                // Safety: We error from the function early if stack_size is 0. We don't care much about whether the block is initialized.
                alloc(stack_layout) as *const u8
            },
            stack_layout
        })
    }

    /// Get the address of the stack top.
    pub fn get_stack_top(&self) -> *const u8 {
        self.stack_address.wrapping_add(self.stack_layout.size())
    }
}

impl Drop for StackContext {
    fn drop(&mut self) {
        unsafe {
            // Safety: The stack_address is guaranteed to be valid (it was allocated on construction). We also keep the layout around to ensure it stays the same between alloc and dealloc.
            dealloc(self.stack_address as *mut u8, self.stack_layout);
        }
    }
}

// Safety: This is safe as StackContext does not contain any internal mutability.
// In fact, its content (that is, the pointer itself and the layout) are immutable after creation.
unsafe impl Sync for StackContext {}
unsafe impl Send for StackContext {}

/// Structure holding the thread local context of a thread.
/// Allocated at thread creation by the creator of the thread.
#[repr(C)]
pub struct ThreadContext {
    /// Pointer to the function this thread should execute after
    /// all its set-up in [thread_trampoline] is done.
    entry_point: fn (usize) -> (),
    /// The argument to call it with.
    arg: usize,
    /// The stack used by this thread.
    ///
    /// `None` for the main thread's stack, since it was not allocated by us
    /// and will never be freed as it'll be the last thread alive.
    ///
    /// `Some` for every other thread.
    stack: Option<StackContext>,
    /// The thread local storage of this thread.
    ///
    /// This is where `#[thread_local]` statics live.
    tls_elf: Once<TlsElf>,
    /// The ThreadHandle of this thread.
    ///
    /// The thread needs to be able to access its own ThreadHandle at anytime
    /// to be able to use mutexes.
    thread_handle: Once<ThreadHandle>,
}

impl fmt::Debug for ThreadContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("ThreadContext")
            .field("entry_point", &self.entry_point)
            .field("arg", &self.arg)
            .field("stack_address", &(self.stack.as_ref().map(|v| v as *const _ as usize).unwrap_or(0)))
            .field("tls", &self.tls_elf)
            .field("thread_handle", &self.thread_handle)
            .finish()
    }
}

/// Context of the main thread. Instead of allocating it at startup, this one lives in the `.data`.
///
/// The handle of the main thread is stored to it at startup.
///
/// ## Mock values:
///
/// Because the main thread is started by the kernel and not libuser, we don't have control or
/// even knowledge of most of the fields that should be in our context. Because of this, we choose
/// to put mock values instead.
/// This includes:
///
/// * `.entry_point`: unused, we are started by the kernel
/// * `.arg`: unused
/// * `.stack`: our stack is not allocated by us, and we don't know its size.
static MAIN_THREAD_CONTEXT: ThreadContext = ThreadContext {
    entry_point: |_| { },
    arg: 0,
    stack: None,
    tls_elf: Once::new(), // will be initialised at startup.
    thread_handle: Once::new(), // will be initialized at startup.
};

/// Get a pointer to this thread's [TLS] region pointed to by `fs`, translated to the flat-memory model.
#[inline]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_my_tls_region() -> *mut TLS {
    let mut tls: *mut TLS;
    unsafe {
        // get the address of the TLS region from fs:0x00 translated to the flat model
        // safe: fs:0x00 is guaranteed by the kernel to hold a valid pointer to itself.
        llvm_asm!("mov $0, fs:0x00" : "=r" (tls) ::: "intel");
    }
    tls
}

/// Get a pointer to this thread's [TLS] region pointed to by `TPIDRRO_EL0`.
#[inline]
#[cfg(target_arch = "aarch64")]
fn get_my_tls_region() -> *mut TLS {
    let mut tls: *mut TLS;
    unsafe {
        // get the address of the TLS region from TPIDRRO_EL0
        // safe: TPIDRRO_EL0 is guaranteed by the kernel to hold a valid pointer to TLS.
        asm!("mrs $0, TPIDRRO_EL0" : "=r" (tls));
    }
    tls
}

/// Get a reference to this thread's [ThreadContext], from the [TLS] region pointed to by `fs`.
///
/// # Panics
///
/// Panics if the thread context hasn't been initialized yet.
/// This happens immediately in the startup of a thread, and relatively early for the main thread.
pub fn get_my_thread_context() -> &'static ThreadContext {
    // read the last bytes of TLS region and treat it as a pointer
    let context_ptr = unsafe {
        // safe: - get_my_tls returns a valid 0x200 aligned ptr,
        //       - .ptr_thread_context is correctly aligned in the TLS region to usize.
        (*get_my_tls_region()).ptr_thread_context as *const ThreadContext
    };
    // The TLS region is initially memset to 0 by the kernel.
    // If the context_ptr is 0 it means it hasn't been written yet.
    debug_assert!(!context_ptr.is_null(), "thread context not initialized yet");
    // create a ref
    unsafe {
        // safe: the context will never be accessed mutably after its allocation,
        //       it is guaranteed to be well-formed since we allocated it ourselves,
        //       the thread context is never deallocated, so 'static is appropriate.
        //       We will want to return an Arc in the future.
        //       => creating a ref is safe.
        &*(context_ptr)
    }
}

/// Get a pointer to this thread's [IPCBuffer], from the [TLS] region pointed to by `fs`.
///
/// [IpcBuffer]: sunrise_libkern::IpcBuffer
#[inline]
pub fn get_my_ipc_buffer() -> *mut IpcBuffer {
    unsafe {
        // safe: just pointer arithmetic
        &(*get_my_tls_region()).ipc_command_buffer as *const _ as *mut _
    }
}

/// Libuser's representation of a thread.
///
/// This is the low-level representation of a thread, kind to `pthread_t` on Unix.
///
/// You can create and start a thread from its `Thread` structure.
///
/// A `Thread` detaches (read "leak resources of") the associated thread when it is dropped,
/// which means that there is no longer any handle to thread and no way to join on it.
///
/// Internally owns the [ThreadContext] for this thread, including its stack.
#[derive(Debug)]
pub struct Thread(ManuallyDrop<Box<ThreadContext>>);

impl Thread {
    /// Start this thread.
    pub fn start(&self) -> Result<(), Error> {
        syscalls::start_thread(&(*self.0).thread_handle.r#try().unwrap())
        .map_err(|v| v.into())
    }

    /// Wait for the thread to exit.
    pub fn join(&self) -> Result<(), Error> {
        let thread_handle = (*self.0).thread_handle.r#try().unwrap().0.as_ref();
        syscalls::wait_synchronization(&[thread_handle], None).map_err(|v| v.into()).map(|_| ())
    }

    /// Allocates resources for a thread. To start it, call [`start`].
    ///
    /// Allocates the stack, sets up the context and TLS, and calls `svcCreateThread`.
    ///
    /// [`start`]: Thread::start
    // todo: Libuser Thread stack guard
    // body: Currently the stack of every non-main thread is allocated in the heap, and no page
    // body: guard protects from stack-overflowing and rewriting all the heap.
    // body:
    // body: This is of course terrible for security, as with this stack overflowing is U.B.
    // body:
    // body: The simpler way to fix this would be to continue allocating the stack on the heap,
    // body: but remap the last page with no permissions with the yet unimplemented svcMapMemory syscall.
    pub fn create(entry: fn (usize) -> (), arg: usize, stack_size: usize) -> Result<Self, Error> {

        let tls_elf = Once::new();
        tls_elf.call_once(TlsElf::allocate);
        // allocate a context
        let context = ManuallyDrop::new(Box::new(ThreadContext {
            entry_point: entry,
            arg,
            stack: Some(StackContext::new(stack_size)?),
            tls_elf: tls_elf,
            thread_handle: Once::new(), // will be rewritten in a second
        }));
        match unsafe {
            // safe: sp is valid and points to memory only owned by the thread,
            //       which is used exclusively for stack.
            syscalls::create_thread(
                thread_trampoline,
                &**context as *const ThreadContext as usize,
                context.stack.as_ref().unwrap().get_stack_top(),
                0,
                0)
        } {
            Err(err) => {
                error!("Failed to create thread {:?}: {}", &*context, err);
                // dealloc the stack and context
                drop(ManuallyDrop::into_inner(context));
                Err(err.into())
            }
            Ok(thread_handle) => {
                // finally, push the handle to the context.
                context.thread_handle.call_once(|| { thread_handle });
                debug!("Allocated new thread: {:?}", context);

                Ok(Self(context))
            }
        }
    }

    /// Get the underlying thread handle.
    pub fn as_thread_ref(&self) -> &ThreadHandle {
        &self.0.thread_handle.r#try().unwrap()
    }
}

/// Small stub executed by every thread but the main thread when they start.
///
/// Saves the pointer to their [ThreadContext] in their [TLS], performs copy of `.tdata` and `.tbss`,
/// calls the routine this thread was meant to perform, and calls `svcExitThread` when it's finished.
///
/// # ABI
///
/// This function is the entry point of a thread, called directly by the kernel, with the
/// argument passed by [Thread::create].
/// It expects this argument to be the address of its `ThreadContext` so it can save it its `TLS`.
///
/// The routine to call and its argument are expected to be found in this `ThreadContext`.
#[cfg(target_arch = "x86")]
extern "fastcall" fn thread_trampoline(thread_context_addr: usize) -> ! {
    debug!("starting from new thread, context at address {:#010x}", thread_context_addr);
    // first save the address of our context in our TLS region
    unsafe {
        // safe: - get_my_tls returns a valid 0x200 aligned ptr,
        //       - .ptr_thread_context is correctly aligned in the TLS region to usize,
        //       - we're a private fn, thread_context_addr is guaranteed by our caller to point to the context.
        (*get_my_tls_region()).ptr_thread_context = thread_context_addr
    };

    // use get_my_thread_context to create a ref for us
    let thread_context = get_my_thread_context();

    // make gs point to our tls
    unsafe {
        // safe: this module guarantees that the TLS region is unique to this thread.
        thread_context.tls_elf.r#try().unwrap().enable_for_current_thread();
    }

    // call the routine saved in the context, passing it the arg saved in the context
    (thread_context.entry_point)(thread_context.arg);

    debug!("exiting thread");
    syscalls::exit_thread()
}

/// Small stub executed by every thread but the main thread when they start.
///
/// Saves the pointer to their [ThreadContext] in their [TLS], performs copy of `.tdata` and `.tbss`,
/// calls the routine this thread was meant to perform, and calls `svcExitThread` when it's finished.
///
/// # ABI
///
/// This function is the entry point of a thread, called directly by the kernel, with the
/// argument passed by [Thread::create].
/// It expects this argument to be the address of its `ThreadContext` so it can save it its `TLS`.
///
/// The routine to call and its argument are expected to be found in this `ThreadContext`.
#[cfg(not(target_arch = "x86"))]
extern fn thread_trampoline(thread_context_addr: usize) -> ! {
    // TODO: figure out aarch64 TLS
    debug!("starting from new thread, context at address {:#010x}", thread_context_addr);
    // first save the address of our context in our TLS region
    unsafe {
        // safe: - get_my_tls returns a valid 0x200 aligned ptr,
        //       - .ptr_thread_context is correctly aligned in the TLS region to usize,
        //       - we're a private fn, thread_context_addr is guaranteed by our caller to point to the context.
        (*get_my_tls_region()).ptr_thread_context = thread_context_addr
    };

    // use get_my_thread_context to create a ref for us
    let thread_context = get_my_thread_context();

    // make gs point to our tls
    unsafe {
        // safe: this module guarantees that the TLS region is unique to this thread.
        thread_context.tls_elf.r#try().unwrap().enable_for_current_thread();
    }

    // call the routine saved in the context, passing it the arg saved in the context
    (thread_context.entry_point)(thread_context.arg);

    debug!("exiting thread");
    syscalls::exit_thread()
}

impl Drop for Thread {
    fn drop(&mut self) {
        // TODO: Properly free resource after thread detach
        // BODY: When detaching a thread, we should ensure that the associated resources (stack,
        // BODY: handle, context, etc...) are properly freed before the Process exits. This can be
        // BODY: done by adding the ThreadContext to a global Vec<> of ThreadContext that gets freed
        // BODY: when the main thread (or the last thread alive?) exits.
    }
}

/// Initialisation of the main thread's thread local structures:
///
/// When a main thread starts, the kernel puts the handle of its own thread in one of its registers.
/// The main thread should perform relocations, and then call this function, which will:
///
/// * put the main thread's handle in [MAIN_THREAD_CONTEXT].
/// * save a pointer to it in its [TLS].
/// * perform copy of `.tdata` and `.tbss` for the main thread.
#[no_mangle] // called from asm
#[cfg(any(not(feature = "build-for-std-app"), doc))]
pub extern fn init_main_thread(handle: u32) {
    let handle = ThreadHandle(Handle::new(handle));

    // save the handle in our context
    MAIN_THREAD_CONTEXT.thread_handle.call_once(|| handle);
    // save the address of our context in our TLS region
    unsafe {
        // safe: - get_my_tls returns a valid 0x200 aligned ptr,
        //       - .ptr_thread_context is correctly aligned in the TLS region to usize,
        (*get_my_tls_region()).ptr_thread_context = &MAIN_THREAD_CONTEXT as *const ThreadContext as usize
    };

    // allocate, enable elf TLS, and save it in our context
    let tls_elf = TlsElf::allocate();
    unsafe {
        // safe: this module guarantees that the TLS region is unique to this thread.
        tls_elf.enable_for_current_thread();
    }
    MAIN_THREAD_CONTEXT.tls_elf.call_once(move || tls_elf);
}
