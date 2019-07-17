//! Interrupt handling.
//!
//! All exceptions are considered unrecoverable errors, and kill the process that issued it.
//!
//! Feature `panic-on-exception` makes the kernel stop and panic when a thread generates
//! an exception. This is useful for debugging.
//!
//! # Macros
//!
//! This module defines the following macros to handle exceptions and interrupts:
//!
//! * [`trap_gate_asm`]\: low-level asm wrapper.
//! * [`generate_trap_gate_handler`]\: high-level rust wrapper.

use crate::i386::structures::idt::{PageFaultErrorCode, Idt};
use crate::i386::instructions::interrupts::sti;
use crate::mem::VirtualAddress;
use crate::paging::kernel_memory::get_kernel_memory;
use crate::i386::PrivilegeLevel;
use crate::scheduler::get_current_thread;
use crate::process::{ProcessStruct, ThreadState};
use crate::sync::{SpinLock, SpinLockIRQ};
use core::sync::atomic::Ordering;

use crate::scheduler;
use crate::i386::gdt::GdtIndex;
use crate::i386::gdt::DOUBLE_FAULT_TASK;
use crate::panic::{kernel_panic, PanicOrigin};
use crate::i386::structures::gdt::SegmentSelector;
use crate::i386::registers::eflags::EFlags;

mod irq;
pub mod syscalls;

/// Checks if our thread was killed, in which case unschedule ourselves.
///
/// # Note
///
/// As this function will be the last that will be called by a thread before dying,
/// caller must make sure all of its scope variables are ok to be leaked.
pub fn check_thread_killed() {
    if scheduler::get_current_thread().state.load(Ordering::SeqCst) == ThreadState::Killed {
        let lock = SpinLockIRQ::new(());
        loop { // in case of spurious wakeups
            let _ = scheduler::unschedule(&lock, lock.lock());
        }
    }
}

/// Represents a register backup.
///
/// The exception wrapper constructs this structure before calling the exception handler,
/// and saves it to the ThreadStruct for debug purposes.
///
/// When the exception handler returns, the wrapper pops it before returning to
/// userspace, allowing precise control over register state.
/// The only exception being `.esp`, which will not be reloaded into `esp`, see [trap_gate_asm].
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[allow(clippy::missing_docs_in_private_items)]
#[allow(missing_docs)]
pub struct UserspaceHardwareContext {
    pub esp: usize,
    pub ebp: usize,
    pub edi: usize,
    pub esi: usize,
    pub edx: usize,
    pub ecx: usize,
    pub ebx: usize,
    pub eax: usize,
    // pushed by cpu:
    pub errcode: usize,
    pub eip: usize,
    pub cs: usize,
    pub eflags: usize,
}

impl core::fmt::Display for UserspaceHardwareContext {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        writeln!(f, "EIP={:#010x} ESP={:#010x} EBP={:#010x}\n\
                     EAX={:#010x} EBX={:#010x} ECX={:#010x} EDX={:#010x}\n\
                     ESI={:#010x} EDI={:#010X}\n\
                     EFLAGS={:?}\n\
                     CS={:?}",
                     self.eip, self.esp, self.ebp,
                     self.eax, self.ebx, self.ecx, self.edx,
                     self.esi, self.edi,
                     EFlags::from_bits_truncate(self.eflags as u32),
                     SegmentSelector(self.cs as u16),
        )
    }
}

// gonna write constants in the code, cause not enough registers.
// just check we aren't hard-coding the wrong values.
const_assert_eq!((GdtIndex::KTls as u16) << 3 | 0b00, 0x18);
const_assert_eq!((GdtIndex::UTlsRegion as u16) << 3 | 0b11, 0x3B);
const_assert_eq!((GdtIndex::UTlsElf as u16) << 3 | 0b11, 0x43);

/// The exception/syscall handler asm wrapper.
///
/// When the cpu handles a Trap/Interrupt gate, it:
///
/// 1. decides if it must switch stacks. If it does, we configured it to switch to the current
///    thread's kernel stack. It will then push userspace `ss` and `esp`.
/// 2. pushes `eflags`, `cs`, `eip`.
/// 3. optionally pushes an errorcode, depending on the exception.
///
/// This is just enough for the cpu to restore the context on `iret` and optionally switch back to
/// the userspace stack.
///
/// On those cpu-pushed registers, we push the rest of the hardware context, so we can restore it
/// at the end of isr. By doing so, we're constructing a [UserspaceHardwareContext] on the stack,
/// but whose `eflags`, `cs` and `eip` fields point to words that were actually pushed by cpu.
///
/// We then call the isr, passing it a pointer to this structure. The isr is free to modify the
/// backed-up registers, including the cpu-pushed ones, and those modification will be popped into
/// the registers at the end of the isr, effectively changing context after we `iret`.
///
/// ## Diagram
///
/// ```txt
///      Privilege changed            Privilege unchanged
///     (e.g. int, syscall)           (e.g. kernel fault,
///                                    int during kernel)
///
///         Page fault
///     +----------------+            +----------------+
///     |       SS       |            |                |
///     +----------------+            +----------------+
///     |      ESP       |            |                |
///     +----------------+            +----------------+
///     |     EFLAGS     | <+      +> |     EFLAGS     | <-+ <-+
///     +----------------+  |      |  +----------------+   |   |
///     |       CS       |  |      |  |       CS       |   |   |
///     +----------------+  |      |  +----------------+   |   | Registers pushed by CPU
///     |      EIP       |  |      |  |      EIP       |   |   |
///     +----------------+  |      |  +----------------+   |   |
///     |   Error code   |  |      |  |   Error code   | <-+   |
///     +****************+  |      |  +****************+       |
///     |   Pushed eax   |  |      |  |   Pushed eax   |       |
///     +----------------+  |      |  +----------------+       |
///     |   Pushed ebx   |  |      |  |   Pushed ebx   |       |
///     +----------------+  |      |  +----------------+       | struct UserspaceHardwareContext
///     |   Pushed ecx   |  |      |  |   Pushed ecx   |       |      passed as an argument
///     +----------------+  |      |  +----------------+       |
///     |   Pushed edx   |  |      |  |   Pushed edx   |       |
///     +----------------+  |      |  +----------------+       |
///     |   Pushed esi   |  |      |  |   Pushed esi   |       |
///     +----------------+  |      |  +----------------+       |
///     |   Pushed edi   |  |      |  |   Pushed edi   |       |
///     +----------------+  |      |  +----------------+       |
///     |   Pushed ebp   |  |      |  |   Pushed ebp   |       |
///     +----------------+  |      |  +----------------+       |
///     | Pushed esp cpy |  |      |  | Pushed esp cpy |     <-+
///     +----------------+  |      |  +----------------+
///     | Pushed arg ptr | -+      +- | Pushed arg ptr |
///     +----------------+            +----------------+
/// ```
///
/// ##### ESP
///
/// The only register that can't be modified by the isr is the `esp` register.
///
/// Because this register is only pushed by the cpu when Privilege changed, we must take extra
/// precautions when reading/writting it from the stack, if we don't want to page fault.
///
/// When reading it we use the pushed `cs` to determine if we did change privilege, in which case
/// we proceed to read it, otherwise we can assume we're running on the same stack,
/// and deduce it from our current `esp` value.
///
/// If the isr modifies `esp` and we're in the Privilege Unchanged situation, there is no way
/// for us to make the cpu use this `esp` after we `iret`, that is make the change effective.
/// For this reason we never bother to copy the `esp` from the UserspaceHardwareContext back to the stack.
///
/// ## Usage
///
/// This macro is intended to be inserted in an `asm!()` block, like this:
///
/// ```rust
/// extern "C" fn my_isr_function(userspace_context: &mut UserspaceHardwareContext) {
///     // irq handling here
/// }
///
/// unsafe {
///     asm!(trap_gate_asm!(has_errorcode: false)
///         :: "i"(my_isr_function as *const u8) :: "volatile", "intel");
/// }
/// ```
///
/// Because `asm!()` expects a literal, `trap_gate_asm` needs to be macro.
///
/// ## Error code
///
/// Some exceptions push an additional errcode on the stack and some don't.
///
/// When one is pushed by the cpu, the isr is still expected to pop it before calling `iret`.
///
/// Because we want to handle both cases in a similar way, for exceptions that are errorcode-less
/// we push a fake error code on the stack as if the cpu did it, and handle everything else in
/// one code path.
///
/// When returning from the exception, the isr will unconditionally pop the errcode,
/// with no regards for whether it was real or not, and call `iret`.
///
/// [UserspaceHardwareContext]: crate::interrupts::UserspaceHardwareContext
#[macro_export] // for docs
macro_rules! trap_gate_asm {
    (has_errorcode: true) => { "
        // Direction flag will be restored on return when iret pops EFLAGS
        cld

        // Construct UserspaceHardwareContext structure
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push ebp
        // Are we in the privilege change state or unchanged ? Look at pushed CS
        mov eax, [esp + 0x24] // cs is 9 registers away at that time * 4 bytes / reg
        and eax, 0x3
        jz 1f

        // priv changed
        // copy the esp pushed by cpu
        mov eax, [esp + 0x2C] // cs is 11 registers away at that time * 4 bytes / reg
        push eax
        jmp 2f
    1:
        // priv unchanged
        // cpu did not push an esp, we are still running on the same stack: compute it
        mov eax, esp
        add eax, 0x2C // old esp is 11 registers away at that time * 4 bytes / reg
        push eax
    2:
        // Push a pointer to the UserspaceHardwareContext we created on the stack
        push esp

        // Great, registers are now fully backed up

        // Load kernel tls segment
        mov ax, 0x18
        mov gs, ax

        // Call some rust code, passing it a pointer to the UserspaceHardwareContext
        call $0

        // Load userspace tls segment
        mov ax, 0x43
        mov gs, ax

        // Restore registers.
        add esp, 0x8 // pop and ignore the pushed arg ptr and esp cpy
        pop ebp
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        add esp, 0x4 // pop the errcode pushed by cpu before iret

        // Return from the interrupt
        iretd
    " };
    (has_errorcode: false) => {
        concat!("
        push 0x0 // push a fake errcode",
        trap_gate_asm!(has_errorcode: true)
        )
    };
}

/// Generates a trap/interrupt gate isr.
///
/// # Goal
///
/// This macro generates a handler for a trap/interrupt gate that will:
///
/// 1. save userspace hardware context in the [ThreadStruct]
/// 2. check boilerplate conditions like if the kernel generated the instruction, or if "panic-on-exception" is on.
/// 3. call a function to handle the interrupt
/// 4. check if the current process was killed, in which case unschedule instead ourselves of returning
/// 5. restore the userspace context
/// 6. `iret`
///
/// This macro is designed to be modular, the idea being that every exception does pretty much the same thing,
/// but in a slightly different way. Because of this we want the step 2 and 3 to be parameterizable.
///
/// The way we do this is defining a few standard strategies for step 2 and 3, letting the user choose
/// which one it wants, and also letting the user override those strategies if they do not fit its use case.
///
/// The macro uses [`trap_gate_asm`] as a the low-level asm handler.
///
/// # Usage
///
/// You are expected to use this macro in the following way:
///
/// ```rust
/// generate_trap_gate_handler!(name: "BOUND Range Exceeded Exception",                 // name of this interrupt, used for logging and when panicking.
///                has_errcode: false,                                                  // whether the cpu pushes an error code on the stack for this interrupt.
///                wrapper_asm_fnname: bound_range_exceeded_exception_asm_wrapper,      // name for the raw asm function this macro will generate. You can then put this function's address in the IDT.
///                wrapper_rust_fnname: bound_range_exceeded_exception_rust_wrapper,    // name for the high-level rust handler this macro will generate.
///                kernel_fault_strategy: panic,                                        // what to do if we were in kernelspace when this interruption happened.
///                user_fault_strategy: panic,                                          // what to do if we were in userspace when this interruption happened, and feature "panic-on-exception" is enabled.
///                handler_strategy: kill                                               // what to for this interrupt otherwise
///);
/// ```
///
/// * The possible values for `kernel_fault_strategy` and `user_fault_strategy` are:
///     * `panic`: causes a kernel panic.
///     * `ignore`: don't do anything for this condition.
///     * `my_handler_func`: calls `my_handler_func` to handle this condition. Useful if you want to override a standard strategy.
/// * The possible values for `handler_strategy` are:
///     * `panic`: causes a kernel panic.
///     * `ignore`: don't do anything for this interrupt.
///     * `kill`: kills the process in which this interrupt originated.
///     * `my_handler_func`: calls `my_handler_func` to handle this interrupt. Useful if you want to override a standard strategy.
///
/// When providing a custom function as strategy, the function must be of signature:
///
/// ```
/// fn my_handler_func(exception_name: &'static str, hwcontext: &mut UserspaceHardwareContext, has_errcode: bool)
/// ```
///
/// The [UserspaceHardwareContext] saved by the wrapper is passed by mut reference so the handler can modify it.
/// Those modifications will be effective as soon as we `iret`.
///
/// # Generates
///
/// This will generate some code along the lines of:
///
/// ```
/// #[naked]
/// extern "C" fn $wrapper_asm_fnname() {
///     unsafe {
///         asm!(interrupt_gate_asm!(has_errorcode: $has_errcode)
///         :: "i"($wrapper_rust_fnname as *const u8) :: "volatile", "intel");
///     }
/// }
///
/// extern "C" fn $wrapper_rust_fnname(userspace_context: &mut UserspaceHardwareContext) {
///
///     if Ring == 0 {
///
///         kernel_panic(&PanicOrigin::KernelFault {                                 //
///             exception_message: format_args!("{}, exception errcode: {:?}",       //
///                 $exception_name,                                                 // kernel_fault_strategy
///                 userspace_context.errcode),                                      // (here: panic)
///             kernel_hardware_context: userspace_context.clone()                   //
///         });                                                                      //
///
///     }
///
///     // we come from userspace, backup the hardware context in the thread struct
///     {
///         *get_current_thread().userspace_hwcontext.lock() = *userspace_context
///     }
///
///     if Ring == 3 && cfg!(feature = "panic-on-exception") {
///
///         kernel_panic(&PanicOrigin::UserspaceFault {                              //
///             exception_message: format_args ! ("{}, exception errcode: {:?}",     //
///                 $exception_name,                                                 // user_fault_strategy
///                 userspace_context.errcode),                                      // (here: panic)
///             userspace_hardware_context: userspace_context.clone()                //
///         });                                                                      //
///
///     }
///
///     {
///         let thread = get_current_thread();                                       //
///         error!("{}, errorcode: {}, in {:#?}",                                    // handler_strategy
///             $exception_name, $hwcontext.errcode, thread);                        // (here: kill)
///         ProcessStruct::kill_process(thread.process.clone());                     //
///     }
///
///     check_thread_killed();
/// }
/// ```
///
/// [ThreadStruct]: crate::process::ThreadStruct
/// [UserspaceHardwareContext]: crate::interrupts::UserspaceHardwareContext
#[macro_export] // for docs
macro_rules! generate_trap_gate_handler {

    // __gen rules are meant to be called recursively.

    /*  standard strategies */

    // if cs == 0 {
    (__gen kernel_fault; name: $exception_name:literal, $hwcontext:ident, errcode: true, strategy: panic) => {
        kernel_panic(&PanicOrigin::KernelFault {
                    exception_message: format_args!("{}, exception errcode: {:?}",
                        $exception_name,
                        $hwcontext.errcode),
                    kernel_hardware_context: $hwcontext.clone()
                });
    };

    (__gen kernel_fault; name: $exception_name:literal, $hwcontext:ident, errcode: false, strategy: panic) => {
        kernel_panic(&PanicOrigin::KernelFault {
                    exception_message: format_args!("{}",
                        $exception_name),
                    kernel_hardware_context: $hwcontext.clone()
                });
    };
    // }

    // if cs == 3 && panic-on-exception {
    (__gen user_fault; name: $exception_name:literal, $hwcontext:ident, errcode: true, strategy: panic) => {
        kernel_panic(&PanicOrigin::UserspaceFault {
                    exception_message: format_args!("{}, exception errcode: {:?}",
                        $exception_name,
                        $hwcontext.errcode),
                    userspace_hardware_context: $hwcontext.clone()
                });
    };

    (__gen user_fault; name: $exception_name:literal, $hwcontext:ident, errcode: false, strategy: panic) => {
        kernel_panic(&PanicOrigin::UserspaceFault {
                    exception_message: format_args!("{}",
                        $exception_name),
                    userspace_hardware_context: $hwcontext.clone()
                });
    };
    // }

    // the handler
    (__gen handler; name: $exception_name:literal, $hwcontext:ident, errcode: true, strategy: panic) => {
        kernel_panic(&PanicOrigin::UserspaceFault {
                    exception_message: format_args!("Unexpected exception: {}, exception errcode: {:?}",
                        $exception_name,
                        $hwcontext.errcode),
                    userspace_hardware_context: $hwcontext.clone()
                });
    };

    (__gen handler; name: $exception_name:literal, $hwcontext:ident, errcode: false, strategy: panic) => {
        kernel_panic(&PanicOrigin::KernelFault {
                    exception_message: format_args!("Unexpected exception: {}",
                        $exception_name),
                    kernel_hardware_context: $hwcontext.clone()
                });
    };

    (__gen handler; name: $exception_name:literal, $hwcontext:ident, errcode: true, strategy: kill) => {
        {
            let thread = get_current_thread();
            error!("{}, errorcode: {}, in {:#?}", $exception_name, $hwcontext.errcode, thread);
            ProcessStruct::kill_process(thread.process.clone());
        }
    };

    (__gen handler; name: $exception_name:literal, $hwcontext:ident, errcode: false, strategy: kill) => {
        {
            let thread = get_current_thread();
            error!("{}, in {:#?}", $exception_name, thread);
            ProcessStruct::kill_process(thread.process.clone());
        }
    };
    // end handler

    // strategy: ignore, shared by all __gen rules
    (__gen $_all:ident; name: $_exception_name:literal, $_hwcontext:ident, errcode: $_errcode:ident, strategy: ignore) => {
        /* ignored */
    };

    // strategy: call external handler, shared by all __gen rules
    //
    // `handler: fn (&'static str, &mut UserspaceHardwareContext, bool)`
    (__gen $_all:ident; name: $exception_name:literal, $hwcontext:ident, errcode: $errcode:ident, strategy: $fnname:ident) => {
        $fnname($exception_name, $hwcontext, $errcode);
    };

    /* ASM wrapper */

    // Generates a naked function with asm that will call `$wrapper_rust_fnname`.
    //
    // Generic over `has_errorcode`.
    (__gen asm_wrapper; $wrapper_asm_fnname:ident, $wrapper_rust_fnname:ident, $errcode:ident) => {
        /// Auto generated function. See [generate_trap_gate_handler].
        #[naked]
        extern "C" fn $wrapper_asm_fnname() {
            unsafe {
                asm!(trap_gate_asm!(has_errorcode: $errcode)
                :: "i"($wrapper_rust_fnname as *const u8) :: "volatile", "intel");
            }
        }
    };

    /* The full wrapper */

    // The rule called to generate an exception handler.
    (
    name: $exception_name:literal,
    has_errcode: $has_errcode:ident,
    wrapper_asm_fnname: $wrapper_asm_fnname:ident,
    wrapper_rust_fnname: $wrapper_rust_fnname:ident,
    kernel_fault_strategy: $kernel_fault_strategy:ident,
    user_fault_strategy: $user_fault_strategy:ident,
    handler_strategy: $handler_strategy:ident
    ) => {

        generate_trap_gate_handler!(__gen asm_wrapper; $wrapper_asm_fnname, $wrapper_rust_fnname, $has_errcode);

        /// Auto generated function. See [generate_trap_gate_handler].
        extern "C" fn $wrapper_rust_fnname(userspace_context: &mut UserspaceHardwareContext) {

            use crate::i386::structures::gdt::SegmentSelector;


            if let PrivilegeLevel::Ring0 = SegmentSelector(userspace_context.cs as u16).rpl() {
                generate_trap_gate_handler!(__gen kernel_fault; name: $exception_name, userspace_context, errcode: $has_errcode, strategy: $kernel_fault_strategy);
            }

            // we come from userspace, backup the hardware context in the thread struct
            {
                *get_current_thread().userspace_hwcontext.lock() = userspace_context.clone();
                // don't leave an Arc in case we're killed in the handler.
            }

            if cfg!(feature = "panic-on-exception") {
                if let PrivilegeLevel::Ring3 = SegmentSelector(userspace_context.cs as u16).rpl() {
                    generate_trap_gate_handler!(__gen user_fault; name: $exception_name, userspace_context, errcode: $has_errcode, strategy: $user_fault_strategy);
                }
            }

            // call the handler
            generate_trap_gate_handler!(__gen handler; name: $exception_name, userspace_context, errcode: $has_errcode, strategy: $handler_strategy);

            check_thread_killed();
        }
    };
}

/*                       */
/* Generate the wrappers */
/*                       */

generate_trap_gate_handler!(name: "Divide Error Exception",
                has_errcode: false,
                wrapper_asm_fnname: divide_by_zero_exception_asm_wrapper,
                wrapper_rust_fnname: divide_by_zero_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Debug Exception",
                has_errcode: false,
                wrapper_asm_fnname: debug_exception_asm_wrapper,
                wrapper_rust_fnname: debug_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: panic
);

generate_trap_gate_handler!(name: "An unexpected non-maskable (but still kinda maskable) interrupt occurred",
                has_errcode: false,
                wrapper_asm_fnname: nmi_exception_asm_wrapper,
                wrapper_rust_fnname: nmi_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: panic
);

generate_trap_gate_handler!(name: "Breakpoint Exception",
                has_errcode: false,
                wrapper_asm_fnname: breakpoint_exception_asm_wrapper,
                wrapper_rust_fnname: breakpoint_exception_rust_wrapper,
                kernel_fault_strategy: ignore,
                user_fault_strategy: ignore,
                handler_strategy: panic
);

generate_trap_gate_handler!(name: "Overflow Exception",
                has_errcode: false,
                wrapper_asm_fnname: overflow_exception_asm_wrapper,
                wrapper_rust_fnname: overflow_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "BOUND Range Exceeded Exception",
                has_errcode: false,
                wrapper_asm_fnname: bound_range_exceeded_exception_asm_wrapper,
                wrapper_rust_fnname: bound_range_exceeded_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Invalid opcode Exception",
                has_errcode: false,
                wrapper_asm_fnname: invalid_opcode_exception_asm_wrapper,
                wrapper_rust_fnname: invalid_opcode_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Device Not Available Exception",
                has_errcode: false,
                wrapper_asm_fnname: device_not_available_exception_asm_wrapper,
                wrapper_rust_fnname: device_not_available_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

/// Double fault handler. Panics the kernel unconditionally.
///
/// This one is called via a Task Gate, we don't generate a wrapper for it.
fn double_fault_handler() {
    kernel_panic(&PanicOrigin::DoubleFault);
}

generate_trap_gate_handler!(name: "Invalid TSS Exception",
                has_errcode: true,
                wrapper_asm_fnname: invalid_tss_exception_asm_wrapper,
                wrapper_rust_fnname: invalid_tss_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: panic
);

generate_trap_gate_handler!(name: "Segment Not Present Exception",
                has_errcode: true,
                wrapper_asm_fnname: segment_not_present_exception_asm_wrapper,
                wrapper_rust_fnname: segment_not_present_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Stack Fault Exception",
                has_errcode: true,
                wrapper_asm_fnname: stack_fault_exception_asm_wrapper,
                wrapper_rust_fnname: stack_fault_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "General Protection Fault Exception",
                has_errcode: true,
                wrapper_asm_fnname: general_protection_fault_exception_asm_wrapper,
                wrapper_rust_fnname: general_protection_fault_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Page Fault Exception",
                has_errcode: true,
                wrapper_asm_fnname: page_fault_exception_asm_wrapper,
                wrapper_rust_fnname: page_fault_exception_rust_wrapper,
                kernel_fault_strategy: kernel_page_fault_panic,
                user_fault_strategy: user_page_fault_panic,
                handler_strategy: user_page_fault_handler
);

/// Overriding the default panic strategy so we can display cr2
fn kernel_page_fault_panic(_exception_name: &'static str, hwcontext: &mut UserspaceHardwareContext, _has_errcode: bool) {
    let errcode = PageFaultErrorCode::from_bits_truncate(hwcontext.errcode as u32);
    let cause_address = crate::paging::read_cr2();

    kernel_panic(&PanicOrigin::KernelFault {
        exception_message: format_args!("Page Fault accessing {:?}, exception errcode: {:?}",
            cause_address,
            errcode),
        kernel_hardware_context: hwcontext.clone()
    });
}

/// Overriding the default panic strategy so we can display cr2
fn user_page_fault_panic(_exception_name: &'static str, hwcontext: &mut UserspaceHardwareContext, _has_errcode: bool) {
    let errcode = PageFaultErrorCode::from_bits_truncate(hwcontext.errcode as u32);
    let cause_address = crate::paging::read_cr2();

    kernel_panic(&PanicOrigin::UserspaceFault {
        exception_message: format_args!("Page Fault accessing {:?}, exception errcode: {:?}",
            cause_address,
            errcode),
        userspace_hardware_context: hwcontext.clone()
    });
}

/// Overriding the default kill strategy so we can display cr2
fn user_page_fault_handler(_exception_name: &'static str, hwcontext: &mut UserspaceHardwareContext, _has_errcode: bool) {
    let errcode = PageFaultErrorCode::from_bits_truncate(hwcontext.errcode as u32);
    let cause_address = crate::paging::read_cr2();

    let thread = get_current_thread();
    error!("Page Fault accessing {:?}, exception errcode: {:?} in {:#?}", cause_address, errcode, thread);
    ProcessStruct::kill_process(thread.process.clone());
}

generate_trap_gate_handler!(name: "x87 FPU floating-point error",
                has_errcode: false,
                wrapper_asm_fnname: x87_floating_point_exception_asm_wrapper,
                wrapper_rust_fnname: x87_floating_point_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Alignment Check Exception",
                has_errcode: true,
                wrapper_asm_fnname: alignment_check_exception_asm_wrapper,
                wrapper_rust_fnname: alignment_check_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Machine-Check Exception",
                has_errcode: false,
                wrapper_asm_fnname: machine_check_exception_asm_wrapper,
                wrapper_rust_fnname: machinee_check_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: panic
);

generate_trap_gate_handler!(name: "SIMD Floating-Point Exception",
                has_errcode: false,
                wrapper_asm_fnname: simd_floating_point_exception_asm_wrapper,
                wrapper_rust_fnname: simd_floating_point_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Virtualization Exception",
                has_errcode: false,
                wrapper_asm_fnname: virtualization_exception_asm_wrapper,
                wrapper_rust_fnname: virtualization_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: kill
);

generate_trap_gate_handler!(name: "Security Exception",
                has_errcode: true,
                wrapper_asm_fnname: security_exception_asm_wrapper,
                wrapper_rust_fnname: security_exception_rust_wrapper,
                kernel_fault_strategy: panic,
                user_fault_strategy: panic,
                handler_strategy: panic
);

// gonna write constants in the code, cause not enough registers.
// just check we aren't hard-coding the wrong values.
const_assert_eq!((GdtIndex::KTls as u16) << 3 | 0b00, 0x18);
const_assert_eq!((GdtIndex::UTlsRegion as u16) << 3 | 0b11, 0x3B);
const_assert_eq!((GdtIndex::UTlsElf as u16) << 3 | 0b11, 0x43);

/// This is the function called on int 0x80.
///
/// The ABI is linuxy, but modified to allow multiple register returns:
///
/// # Inputs
///
/// - eax  system call number
/// - ebx  arg1
/// - ecx  arg2
/// - edx  arg3
/// - esi  arg4
/// - edi  arg5
/// - ebp  arg6
///
/// # Outputs
///
/// - eax  error code
/// - ebx  ret1
/// - ecx  ret2
/// - edx  ret3
/// - esi  ret4
/// - edi  ret5
/// - ebp  ret6
///
/// What this wrapper does is creating an instance of the Registers structure on the stack as argument
/// to the syscall dispatcher. The syscall dispatcher will then modify this structure to reflect what
/// the registers should look like on syscall exit, and the wrapper pops those modified values.
///
/// We don't use the x86-interrupt llvm feature because syscall arguments are passed in registers, and
/// it does not enable us to access those saved registers.
///
/// We do *NOT* restore registers before returning, as they all are used for parameter passing.
/// It is the caller's job to save the one it needs.
#[naked]
extern "C" fn syscall_handler() {
    unsafe {
        asm!("
        cld         // direction flag will be restored on return when iret pops EFLAGS
        // Construct Registers structure - see syscalls for more info
        push ebp
        push edi
        push esi
        push edx
        push ecx
        push ebx
        push eax
        // Load kernel tls segment
        mov ax, 0x18
        mov gs, ax
        // Push pointer to Registers structure as argument
        push esp
        call $0
        // Load userspace tls segment
        mov ax, 0x43
        mov gs, ax
        // Restore registers.
        mov ebx, [esp + 0x08]
        mov ecx, [esp + 0x0C]
        mov edx, [esp + 0x10]
        mov esi, [esp + 0x14]
        mov edi, [esp + 0x18]
        mov ebp, [esp + 0x1C]
        mov eax, [esp + 0x04]
        add esp, 0x20
        iretd
        " :: "i"(syscalls::syscall_handler_inner as *const u8) :: "volatile", "intel" );
    }
}

lazy_static! {
    /// IDT address. Initialized in `init()`.
    static ref IDT: SpinLock<Option<VirtualAddress>> = SpinLock::new(None);
}

/// Initialize the interrupt subsystem. Sets up the PIC and the IDT.
///
/// # Safety
///
/// Should only be called once!
#[allow(clippy::cast_ptr_alignment)] // this function is x86_32 only
#[allow(clippy::fn_to_numeric_cast)] // this function is x86_32 only
pub unsafe fn init() {
    crate::i386::interrupt::init();

    {
        let page = get_kernel_memory().get_page();
        let idt = page.addr() as *mut u8 as *mut Idt;
        unsafe {
            (*idt).init();
            (*idt).divide_by_zero.set_handler_fn(divide_by_zero_exception_asm_wrapper);
            (*idt).debug.set_handler_fn(debug_exception_asm_wrapper);
            (*idt).non_maskable_interrupt.set_handler_fn(nmi_exception_asm_wrapper);
            (*idt).breakpoint.set_handler_fn(breakpoint_exception_asm_wrapper);
            (*idt).overflow.set_handler_fn(overflow_exception_asm_wrapper);
            (*idt).bound_range_exceeded.set_handler_fn(bound_range_exceeded_exception_asm_wrapper);
            (*idt).invalid_opcode.set_handler_fn(invalid_opcode_exception_asm_wrapper);
            (*idt).device_not_available.set_handler_fn(device_not_available_exception_asm_wrapper);
            DOUBLE_FAULT_TASK.lock().set_ip(double_fault_handler as u32);
            (*idt).double_fault.set_handler_task_gate(GdtIndex::FTSS.selector());
            // coprocessor_segment_overrun
            (*idt).invalid_tss.set_handler_fn(invalid_tss_exception_asm_wrapper);
            (*idt).segment_not_present.set_handler_fn(segment_not_present_exception_asm_wrapper);
            (*idt).stack_segment_fault.set_handler_fn(stack_fault_exception_asm_wrapper);
            (*idt).general_protection_fault.set_handler_fn(general_protection_fault_exception_asm_wrapper);
            (*idt).page_fault.set_handler_fn(page_fault_exception_asm_wrapper);
            (*idt).x87_floating_point.set_handler_fn(x87_floating_point_exception_asm_wrapper);
            (*idt).alignment_check.set_handler_fn(alignment_check_exception_asm_wrapper);
            (*idt).machine_check.set_handler_fn(machine_check_exception_asm_wrapper);
            (*idt).simd_floating_point.set_handler_fn(simd_floating_point_exception_asm_wrapper);
            (*idt).virtualization.set_handler_fn(virtualization_exception_asm_wrapper);
            (*idt).security_exception.set_handler_fn(security_exception_asm_wrapper);

            for (i, handler) in irq::IRQ_HANDLERS.iter().enumerate() {
                (*idt).interrupts[i].set_interrupt_gate_addr(*handler as u32);
            }

            // Add entry for syscalls
            let syscall_int = (*idt)[0x80].set_interrupt_gate_addr(syscall_handler as u32);
            syscall_int.set_privilege_level(PrivilegeLevel::Ring3);
            syscall_int.disable_interrupts(false);
        }
        let mut lock = IDT.lock();
        *lock = Some(page);
        (*idt).load();
    }

    sti();
}
