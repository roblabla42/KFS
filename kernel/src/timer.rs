//! The core timing of Sunrise.

use super::event::Waitable;
use crate::sync::{Mutex, SpinLockIRQ};
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::process::ThreadStruct;

/// Trait representing the implementation of the main timer used by the kernel.
pub trait TimerDriver {
    /// Function in charge of setting up a new one shot timer.
    fn set_oneshot_timer(&mut self, interval: u64);

    /// Return the target tick to wait on.
    fn get_target_ticks(&self, ticks: u64) -> u64;

    /// Check if we are equal or past the given target ticks.
    ///
    /// # Note:
    /// - The driver *must* asure that the ticks are monotonic.
    fn is_after_or_equal_main_ticks(&self, target_ticks: u64) -> bool;

    /// Convert the given nanoseconds to timer ticks.
    fn convert_ns_to_ticks(&self, ns: u64) -> u64;
}

use core::cmp::Ordering as CmpOrdering;

/// Timer state.
#[derive(Debug)]
struct TimerState {
    /// The waiting thread.
    target_waiter: Arc<ThreadStruct>,

    /// Target ticks to be wakup at.
    target_ticks: u64
}

impl TimerState {
    /// Create a new TimerState with a given target ticks.
    ///
    /// # Note:
    /// - The TimerState will be linked to the current thread.
    pub fn new(target_ticks: u64) -> Self {
        TimerState {
            target_waiter: crate::scheduler::get_current_thread(),
            target_ticks
        }
    }
}

impl Ord for TimerState {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.target_ticks.cmp(&other.target_ticks)
    }
}

impl PartialOrd for TimerState {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        self.target_ticks.partial_cmp(&other.target_ticks)
    }
}

impl PartialEq for TimerState {
    fn eq(&self, other: &Self) -> bool {
        self.target_ticks == other.target_ticks
    }
}

impl Eq for TimerState {}

/// Global state for all threads currently sleeping.
static TIMER_STATES: SpinLockIRQ<Vec<TimerState>> = SpinLockIRQ::new(Vec::new());

#[cfg(any(target_arch="x86", rustdoc))]
use crate::devices::hpet::TIMER_DRIVER;

/// Returns a stream of event that trigger every `ns` amount of nanoseconds.
/// 
/// # Note
/// 
/// - If the timer resolution cannot handle it, this is not going to be accurate.
/// - Minimal resolution for HPET (10Mhz) / HPET QEMU (100Mhz): 100ns / 10ns
pub fn wait_ns(ns: u64) -> impl Waitable {
    TimerEvent::new(ns)
}

#[derive(Debug)]
/// A stream of event that trigger after `ns` amount of nanoseconds.
pub struct TimerEvent {
    /// The count of ticks to wait to atain the expected amount of nanoseconds.
    ticks: u64,

    /// The target ticks value that we are currently waiting on.
    target_ticks: Mutex<u64>
}

impl TimerEvent {
    /// Create a new timer event instance from the time to wait (in ns).
    pub fn new(ns: u64) -> Self {
        let timer_driver = TIMER_DRIVER.r#try().expect("Timer driver is not initialized!").lock();
        let ticks = timer_driver.convert_ns_to_ticks(ns);

        TimerEvent {
            ticks,
            target_ticks: Mutex::new(timer_driver.get_target_ticks(ticks))
        }
    }

    /// Get the target ticks
    pub fn get_target_ticks(&self) -> u64 {
        *self.target_ticks.lock()
    }
}

impl Waitable for TimerEvent {
    fn register(&self) {
        {
            let target_ticks = self.target_ticks.lock();
            assert!(*target_ticks != 0, "TimerEvent already registered!");
        }

        register_timer_event(self);
    }

    fn is_signaled(&self) -> bool {
        let mut target_ticks = self.target_ticks.lock();
        let result = {
            let timer_driver = TIMER_DRIVER.r#try().expect("Timer driver is not initialized!").lock();
            !timer_driver.is_after_or_equal_main_ticks(*target_ticks)
        };

        if result {
            *target_ticks = 0;
        }

        result
    }
}

/// Register a timer waiter.
fn register_timer_event(event: &TimerEvent) {
    let mut states = TIMER_STATES.lock();
    let target_ticks = event.get_target_ticks();

    let insert_position = states.iter().position(|x| x.target_ticks >= target_ticks);
    let need_oneshot_setup = insert_position.is_none() || insert_position == Some(0);

    states.insert(insert_position.unwrap_or(0), TimerState::new(target_ticks));

    // If no oneshot was setup or this timer is lower than the current in usage, we need to do the oneshot setup again.
    if need_oneshot_setup {
        let next_oneshot = states.get(0);

        // Setup next oneshot if present.
        if let Some(next_oneshot) = next_oneshot {
            let mut timer_driver = TIMER_DRIVER.r#try().expect("Timer driver is not initialized!").lock();
            timer_driver.set_oneshot_timer(next_oneshot.target_ticks);
        }
    }
}

/// Signal the scheduler and waiters that a oneshot has ended.
///
/// #Note:
///
/// - This must be called by the timer IRQ handler.
pub fn wakeup_waiters() {
    let mut timer_driver = TIMER_DRIVER.r#try().expect("Timer driver is not initialized!").lock();

    let mut states = TIMER_STATES.lock();

    loop {
        // Get the next oneshot and setup it if we have one
        let next_oneshot_idx = states.iter().position(|x| timer_driver.is_after_or_equal_main_ticks(x.target_ticks)).unwrap_or_else(|| states.len());

        let next_oneshot = states.get(next_oneshot_idx);

        if let Some(next_oneshot) = next_oneshot {
            timer_driver.set_oneshot_timer(next_oneshot.target_ticks);
        }

        // Remove threads from the state Vec and schedule them.
        for state in states.drain(..next_oneshot_idx) {
            // As the vec is always sorted, we just remove the first element every time
            crate::scheduler::add_to_schedule_queue(state.target_waiter);
        }

        let next_oneshot = states.get(0);
        if next_oneshot.is_none() {
            break;
        }

        let next_oneshot = next_oneshot.unwrap();

        // The next oneshot is still past accumulator?
        if !timer_driver.is_after_or_equal_main_ticks(next_oneshot.target_ticks) {
            break;
        }

        // If we went over our next oneshot's target tick, let's run the loop again!
        log::debug!("Oneshot overrun retrying...");
    }
}