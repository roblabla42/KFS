//! UserspaceError and KernelError

use failure::Backtrace;
use crate::paging::error::MmError;
use core::fmt::{self, Display};

pub use kfs_libkern::error::KernelError as UserspaceError;

#[derive(Debug, Clone, Copy)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
pub enum ArithmeticOperation { Add, Sub, Mul, Div, Mod, Pow }

impl Display for ArithmeticOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ArithmeticOperation::Add => write!(f, "+"),
            ArithmeticOperation::Sub => write!(f, "-"),
            ArithmeticOperation::Mul => write!(f, "*"),
            ArithmeticOperation::Div => write!(f, "/"),
            ArithmeticOperation::Mod => write!(f, "%"),
            ArithmeticOperation::Pow => write!(f, "**"),
        }
    }
}

/// Kernel Error.
///
/// Used pretty much everywhere that an error can occur. Holds the reason of the error,
/// and a backtrace of its origin, for debug.
///
/// When a KernelError must be propagated to userspace, i.e. a syscall failed, it must be
/// converted to a [UserspaceError].
#[derive(Debug, Fail)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
pub enum KernelError {
    #[fail(display = "Frame allocation error: physical address space exhausted")]
    PhysicalMemoryExhaustion {
        backtrace: Backtrace
    },
    #[fail(display = "Virtual allocation error: virtual address space exhausted")]
    VirtualMemoryExhaustion {
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid address: address {:#010x} is considered invalid", address)]
    InvalidAddress {
        address: usize,
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid size: size {} is considered invalid", size)]
    InvalidSize {
        size: usize,
        backtrace: Backtrace,
    },
    #[fail(display = "Alignment error: expected alignment {}, got {}", needed, given)]
    AlignmentError {
        given: usize,
        needed: usize,
        backtrace: Backtrace,
    },
    #[fail(display = "Arithmetic error: {} {} {} would cause an overflow", lhs, operation, rhs)]
    WouldOverflow {
        lhs: usize,
        rhs: usize,
        operation: ArithmeticOperation,
        backtrace: Backtrace,
    },
    #[fail(display = "Length error: length is 0")]
    ZeroLengthError {
        backtrace: Backtrace,
    },
    #[fail(display = "Memory management error: {}", _0)]
    MmError(MmError),
    #[fail(display = "Process was killed before finishing operation")]
    ProcessKilled {
        backtrace: Backtrace,
    },
    #[fail(display = "Thread was already started")]
    ThreadAlreadyStarted {
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid combination of values passed.")]
    InvalidCombination {
        backtrace: Backtrace,
    },
    #[fail(display = "The passed value ({}) would overflow the maximum ({}).", value, maximum)]
    ExceedingMaximum {
        value: u64,
        maximum: u64,
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid kernel capability u32: {}", _0)]
    InvalidKernelCaps {
        kcap: u32,
        backtrace: Backtrace,
    },
    #[fail(display = "Value is reserved for future use.")]
    ReservedValue {
        backtrace: Backtrace,
    },
    #[doc(hidden)]
    #[fail(display = "Should never ever ***EVER*** be returned")]
    ThisWillNeverHappenButPleaseDontMatchExhaustively,
}

impl From<KernelError> for UserspaceError {
    fn from(err: KernelError) -> UserspaceError {
        match err {
            KernelError::PhysicalMemoryExhaustion { .. } => UserspaceError::MemoryFull,
            KernelError::VirtualMemoryExhaustion { .. } => UserspaceError::MemoryFull,
            KernelError::ThreadAlreadyStarted { .. } => UserspaceError::ProcessAlreadyStarted,
            KernelError::InvalidAddress { .. } => UserspaceError::InvalidAddress,
            KernelError::InvalidSize { .. } => UserspaceError::InvalidSize,
            KernelError::ZeroLengthError { .. } => UserspaceError::InvalidSize,
            // TODO: AlignementError should discriminate unaligned size and unaligned address
            // BODY: We can only convey InvalidSize and InvalidAddress to userspace.
            // BODY: We should define two check functions, that work on a either size or an address,
            // BODY: and can propagate the right error to userspace automatically.
            // BODY:
            // BODY: We must then remove KernelError::AlignmentError.
            KernelError::AlignmentError { .. } => UserspaceError::InvalidAddress,
            KernelError::InvalidCombination { .. } => UserspaceError::InvalidCombination,
            KernelError::ExceedingMaximum { .. } => UserspaceError::ExceedingMaximum,
            KernelError::InvalidKernelCaps { .. } => UserspaceError::InvalidKernelCaps,
            KernelError::ReservedValue { .. } => UserspaceError::ReservedValue,
            //KernelError::
            KernelError::ThisWillNeverHappenButPleaseDontMatchExhaustively => unreachable!(),
            // todo
            _ => unimplemented!("Unmatched Error: {}", err)
        }
    }
}

