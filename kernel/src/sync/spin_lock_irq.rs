//! Lock disabling IRQs while held
//!
//! See the [sync] module documentation.
//!
//! [sync]: crate::sync

use crate::i386::instructions::interrupts;
use spin::{Mutex as SpinLock, MutexGuard as SpinLockGuard};
use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU8, Ordering};
use super::INTERRUPT_DISARM;
use crate::cpu_locals::ARE_CPU_LOCALS_INITIALIZED_YET;

/// Interrupt disable counter.
///
/// # Description
///
/// Allows recursively disabling interrupts while keeping a sane behavior.
/// Should only be manipulated through [enable_interrupts],
/// [disable_interrupts], and [decrement_lock_count].
///
/// Used by the SpinLockIRQ to implement recursive irqsave logic.
#[thread_local]
static INTERRUPT_DISABLE_COUNTER: AtomicU8 = AtomicU8::new(0);

/// Decrement the interrupt disable counter.
///
/// Look at documentation for [INTERRUPT_DISABLE_COUNTER] to know more.
///
/// # Safety
///
/// Should be called in pairs with [disable_interrupts] or [decrement_lock_count],
/// otherwise the counter will get out of sync and deadlocks will likely occur.
pub unsafe fn enable_interrupts() {
    if !INTERRUPT_DISARM.load(Ordering::SeqCst) && ARE_CPU_LOCALS_INITIALIZED_YET.load(Ordering::SeqCst) && INTERRUPT_DISABLE_COUNTER.fetch_sub(1, Ordering::SeqCst) == 1 {
        unsafe { interrupts::sti() }
    }
}

/// Decrement the interrupt disable counter without re-enabling interrupts.
///
/// Used to decrement counter while keeping interrupts disabled before an iret.
/// Look at documentation for [INTERRUPT_DISABLE_COUNTER] to know more.
///
/// # Safety
///
/// Should be called in pairs with [enable_interrupts],
/// otherwise the counter will get out of sync and deadlocks will likely occur.
///
/// Additionally, this should only be used when interrupts are about to be enabled anyway,
/// such as by an iret to userspace.
pub unsafe fn decrement_lock_count() {
    if !INTERRUPT_DISARM.load(Ordering::SeqCst) && ARE_CPU_LOCALS_INITIALIZED_YET.load(Ordering::SeqCst) {
        let _ = INTERRUPT_DISABLE_COUNTER.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Increment the interrupt disable counter.
///
/// Look at documentation for [INTERRUPT_DISABLE_COUNTER] to know more.
///
/// # Safety
///
/// Should be called in pairs with [enable_interrupts],
/// otherwise the counter will get out of sync and deadlocks will likely occur.
pub unsafe fn disable_interrupts() {
    if !INTERRUPT_DISARM.load(Ordering::SeqCst) && ARE_CPU_LOCALS_INITIALIZED_YET.load(Ordering::SeqCst) && INTERRUPT_DISABLE_COUNTER.fetch_add(1, Ordering::SeqCst) == 0 {
        unsafe { interrupts::cli() }
    }
}


/// Permanently disables the interrupts. Forever.
///
/// Only used by the panic handlers!
///
/// Simply sets [INTERRUPT_DISARM].
pub unsafe fn permanently_disable_interrupts() {
    INTERRUPT_DISARM.store(true, Ordering::SeqCst);
    unsafe { interrupts::cli() }
}

/// SpinLock that disables IRQ.
///
/// # Description
///
/// This type behaves like a spinlock from the Linux crate. For simplicity of
/// use and implementation. The mapping is as follows:
///
/// - `lock` behaves like a `spinlock_irqsave`. It returns a guard.
/// - Dropping the guard behaves like `spinlock_irqrestore`
///
/// This means that locking a spinlock disables interrupts until all spinlocks
/// have been dropped.
///
/// Note that it is allowed to lock/unlock the locks in a different order. It uses
/// a global counter to disable/enable interrupts. View [INTERRUPT_DISABLE_COUNTER]
/// documentation for more information.
pub struct SpinLockIRQ<T: ?Sized> {
    /// SpinLock we wrap.
    internal: SpinLock<T>
}

impl<T> SpinLockIRQ<T> {
    /// Creates a new spinlockirq wrapping the supplied data.
    pub const fn new(internal: T) -> SpinLockIRQ<T> {
        SpinLockIRQ {
            internal: SpinLock::new(internal)
        }
    }

    /// Consumes this SpinLockIRQ, returning the underlying data.
    pub fn into_inner(self) -> T {
        self.internal.into_inner()
    }
}

impl<T: ?Sized> SpinLockIRQ<T> {
    /// Disables interrupts and locks the mutex.
    pub fn lock(&self) -> SpinLockIRQGuard<'_, T> {
        unsafe {
            // Safety: Paired with enable_interrupts in the impl of Drop for SpinLockIrqGuard.
            disable_interrupts();
        }

        // TODO: Disable preemption.
        // TODO: Spin acquire

        // lock
        let internalguard = self.internal.lock();
        SpinLockIRQGuard(ManuallyDrop::new(internalguard))
    }

    /// Disables interrupts and locks the mutex.
    pub fn try_lock(&self) -> Option<SpinLockIRQGuard<'_, T>> {
        unsafe {
            // Safety: Paired with enable_interrupts in the impl of Drop for SpinLockIrq,
            // or in case a guard is not created, later in this function.
            disable_interrupts();
        }

        // TODO: Disable preemption.
        // TODO: Spin acquire

        // lock
        match self.internal.try_lock() {
            Some(internalguard) => Some(SpinLockIRQGuard(ManuallyDrop::new(internalguard))),
            None => {
                // We couldn't lock. Restore irqs and return None
                unsafe {
                    // Safety: Paired with disable_interrupts above in the case that a guard is not created.
                    enable_interrupts();
                }
                None
            }
        }
    }

    /// Force unlocks the lock.
    pub unsafe fn force_unlock(&self) {
        self.internal.force_unlock()
    }
}

impl<T: fmt::Debug> fmt::Debug for SpinLockIRQ<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Some(d) => {
                write!(f, "SpinLockIRQ {{ data: ")?;
                d.fmt(f)?;
                write!(f, "}}")
            },
            None => write!(f, "SpinLockIRQ {{ <locked> }}")
        }
    }
}

/// The SpinLockIrq lock guard.
#[derive(Debug)]
pub struct SpinLockIRQGuard<'a, T: ?Sized>(ManuallyDrop<SpinLockGuard<'a, T>>);

impl<'a, T: ?Sized + 'a> Drop for SpinLockIRQGuard<'a, T> {
    fn drop(&mut self) {
        // TODO: Spin release
        // unlock
        unsafe { ManuallyDrop::drop(&mut self.0); }

        unsafe {
            // Safety: paired with disable_interrupts in SpinLockIRQ::{lock, try_lock}, which returns
            // this guard to re-enable interrupts when it is dropped.
            enable_interrupts();
        }

        // TODO: Enable preempt
    }
}

impl<'a, T: ?Sized + 'a> Deref for SpinLockIRQGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &*self.0
    }
}

impl<'a, T: ?Sized + 'a> DerefMut for SpinLockIRQGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.0
    }
}
