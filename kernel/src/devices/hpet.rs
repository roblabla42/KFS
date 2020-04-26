//! HPET driver implementation.
//!
//! HPET documentation: https://web.archive.org/web/20190411220000/https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf
use crate::frame_allocator::PhysicalMemRegion;
use crate::mem::PhysicalAddress;
use crate::paging;
use crate::paging::MappingAccessRights;
use crate::paging::PAGE_SIZE;
use static_assertions::assert_eq_size;
use sunrise_libutils::io::{Io, Mmio};

use core::fmt;
use core::fmt::Debug;
use core::fmt::Formatter;

use crate::timer;

use spin::Once;
use crate::sync::SpinLockIRQ;

bitfield! {
    /// Represent the lower part of the General Capabilities and ID Register.
    #[derive(Clone, Copy, Debug)]
    pub struct HpetIdRegister(u32);
    /// Indicates which revision of the function is implemented; must not be 0.
    pub revision_id, _ : 7, 0;
    /// The amount of timers - 1.
    pub timer_count_minus_one, _ : 12, 8;

    /// If this bit is 1, HPET main counter is capable of operating in 64 bit mode.
    pub counter_size_capability, _: 13;

    /// If this bit is 1, HPET is capable of using "legacy replacement" mapping.
    pub legacy_rt_capability, _: 15;

    /// Represent the HPET vendor id (most likely PCI vendor id?)
    pub vendor_id, _: 31, 16;
}

bitfield! {
    /// Represent the General Configuration Register.
    #[derive(Clone, Copy, Debug)]
    pub struct HpetGeneralConfigurationRegister(u32);
    /// Control HPET activation (control main timer activation state and timer interrupts activation).
    pub enable_config, set_enable_config: 0;
    /// Control "legacy replacement" mapping activation state.
    pub legacy_rt_config, set_legacy_rt_config: 1;
}

bitfield! {
    /// Represent a Timer Configuration Register.
    #[derive(Clone, Copy, Debug)]
    pub struct HpetTimerConfigurationRegister(u32);
    /// Control Timer Interrupt Type: 0 = Edge Trigger, 1 = Level Trigger
    pub interrupt_type, set_interrupt_type: 1;
    /// Control Timer Interrupt.
    pub interrupt_enable, set_interrupt_enable: 2;
    /// Control Timer Type: 0 = One Shot, 1 = Periodic
    pub timer_type, set_timer_type: 3;

    /// true if this timer is capable of periodic timer.
    pub periodic_interrupt_capability, _: 4;

    /// If this bit is 1, this timer is capable of operating in 64 bit mode.
    pub size_capability, _: 5;

    /// Set to 1 to allow software to write the accumulator data.
    ///
    /// # Note
    ///
    /// This auto-clear.
    pub accumulator_config, set_accumulator_config: 6;

    /// Set to 1 to force a 64 bit timer to operate as 32 bit one
    ///
    /// # Note
    ///
    /// This as no effect on a 32 bit timer.
    pub is_32bit_mode, set_32bit_mode: 8;

    /// Timer Interrupt Route: This indicate the routing in the I/O APIC
    ///
    /// # Note
    ///
    /// If the LegacyReplacement Route bit is set, then Timers 0 and 1 will have a different routing, and this bit field has no effect for those two timers.
    ///
    /// If the Timer FSB Interrupt bit is set, then the interrupt will be delivered directly to the FSB, and this bit field has no effect.
    pub interrupt_route, set_interrupt_route: 13, 9;

    /// Timer FSB Interrupt: force the interrupts to be delivered directly as FSB messages, rather than using the I/O APIC.
    pub fsb_interrupt, set_fsb_interrupt: 14;

    /// Timer FSB Interrupt Delivery capability.
    pub fsb_interrupt_capability, _: 15;
}

#[allow(clippy::missing_docs_in_private_items)]
#[repr(packed)]
/// Representation of HPET non variable registers.
pub struct HpetRegister {
    /// Information about the HPET model.
    pub identifier: Mmio<HpetIdRegister>, // 0x0
    /// Main counter tick period in femtoseconds (10^-15 seconds).
    /// Must not be zero, must be less or equal to 0x05F5E100, or 100 nanoseconds.
    pub period: Mmio<u32>, // 0x4
    _reserved0: u64, // 0x8
    /// General Configuration Register.
    pub general_configuration: Mmio<HpetGeneralConfigurationRegister>, // 0x10
    _reserved1: u32, // 0x14
    _reserved2: u64, // 0x18
    /// General Interrupt Status Register.
    pub general_interrupt_status: Mmio<u32>, // 0x20
    _reserved3: [u8; 0xCC], // 0x24
    /// main counter value.
    pub main_counter_value: Mmio<u64>, // 0xF0
    _reserved4: u64, // 0xF8
}

impl Debug for HpetRegister {
    /// Debug does not access reserved registers.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("HpetRegister")
            .field("identifier", &self.identifier)
            .field("period", &self.period)
            .field("general_configuration", &self.general_configuration)
            .field("general_interrupt_status", &self.general_interrupt_status)
            .field("main_counter_value", &self.main_counter_value)
            .finish()
    }
}

#[derive(Debug)]
/// Representation of an HPET timer registers.
pub struct HpetTimerRegister {
    /// The configuration and capabilities register of this timer.
    pub config: Mmio<HpetTimerConfigurationRegister>,
    /// Routing capability (IRQ0 to IRQ31 on the I/O APIC).
    pub interrupt_route_capability: Mmio<u32>,
    /// The comparator value register low part.
    pub comparator_value_low: Mmio<u32>,
    /// The comparator value register high part.
    pub comparator_value_high: Mmio<u32>,
    /// The FSB Interrupt Route register lower part (value during FSB interrupt message).
    pub fsb_value: Mmio<u32>,
    /// The FSB Interrupt Route register higher part (address used during FSB interrupt message).
    pub fsb_address: Mmio<u32>,
}

#[derive(Debug)]
/// Represent an HPET device.
pub struct Hpet {
    /// The mmio address of this HPET device.
    pub inner: &'static mut HpetRegister,

    /// Cached value of ``Hpet::period``.
    period: u32,

    /// The count of timer of this HPET device.
    timer_count: u32,
}

#[derive(Debug)]
/// Represent an HPET timer.
pub struct HpetTimer {
    /// The mmio address of this HPET timer.
    inner: &'static mut HpetTimerRegister,

    /// Cached value of ``HpetTimerConfigurationRegister::size_capability``.
    support_64bit: bool,

    /// Cached value of ``HpetTimerConfigurationRegister::periodic_interrupt_capability``.
    support_periodic_interrupt: bool,

    /// Cached value of ``HpetTimerConfigurationRegister::fsb_interrupt_capability``.
    support_fsb_interrupt: bool,

    /// Cached value of ``HpetTimerRegister::interrupt_route_capability``.
    interrupt_route_capability: u32,
}

impl HpetTimer {
    /// This is the maximum IRQ lines supported by the HPET.
    const MAX_IRQ: u32 = 0x1F;

    /// Create a new HPET timer instance from MMIO registers.
    ///
    /// # Safety
    ///
    /// If inner is mutably aliased, this will cause UB. We need to ensure that
    /// we are the unique owner of the HpetTimerRegister pointer.
    unsafe fn new(inner: *mut HpetTimerRegister) -> Self {
        let mut res = HpetTimer {
            inner: inner.as_mut().unwrap(),
            support_64bit: false,
            support_periodic_interrupt: false,
            support_fsb_interrupt: false,
            interrupt_route_capability: 0,
        };

        let config = res.inner.config.read();

        res.support_64bit = config.size_capability();
        res.support_periodic_interrupt = config.periodic_interrupt_capability();
        res.support_fsb_interrupt = config.fsb_interrupt_capability();
        res.interrupt_route_capability = res.inner.interrupt_route_capability.read();
        res
    }

    /// Return true if this timer is a 64 bits timer.
    pub fn support_64bit(&self) -> bool {
        self.support_64bit
    }

    /// Return true if this timer supports periodic interrupt.
    pub fn support_periodic_interrupt(&self) -> bool {
        self.support_periodic_interrupt
    }

    /// Return true if this timer supports fsb interrupt.
    pub fn support_fsb_interrupt(&self) -> bool {
        self.support_fsb_interrupt
    }

    /// Return true if the timer support routing to the given IRQ.
    pub fn support_interrupt_routing(&self, index: u32) -> bool {
        if index > Self::MAX_IRQ {
            return false;
        }

        let irq_mask = 1 << index;
        (self.interrupt_route_capability & irq_mask) == irq_mask
    }

    /// Set the routing for the interrupt to the I/O APIC.
    ///
    /// # Panics
    ///
    /// Panics if the given interrupt route is not supported by this hpet timer.
    pub fn set_interrupt_route(&mut self, index: u32) {
        assert!(self.support_interrupt_routing(index), "Illegal interrupt route (as claimed). Supported routes: {}.", self.interrupt_route_capability);
        let mut config = self.inner.config.read();
        config.set_interrupt_route(index);
        self.inner.config.write(config);

        let config = self.inner.config.read();
        assert!(config.interrupt_route() == index, "Illegal interrupt route (as tested). Supported routes: {}.", self.interrupt_route_capability);
    }

    /// Set the timer comparactor value
    pub fn set_comparator_value(&mut self, value: u64) {
        self.inner
            .comparator_value_low
            .write((value & 0xFFFF_FFFF) as u32);
        self.inner
            .comparator_value_high
            .write((value >> 32) as u32);
    }

    /// Set the timer accumulator value.
    ///
    /// # Note
    ///
    /// The timer MUST be in periodic mode.
    pub fn set_accumulator_value(&mut self, value: u64) {
        // We update the accumulator register two times.
        // TODO: Test the hardware behaviour on partial write of the HPET accumulator
        // BODY: Because we are running on i386, this cause issue on QEMU.
        // BODY: In fact, QEMU clear the accumulator flag on every partial write.
        // BODY: The question here is: Is that normal or a bug in QEMU?
        let mut config = self.inner.config.read();
        config.set_accumulator_config(true);
        self.inner.config.write(config);
        self.inner
            .comparator_value_low
            .write((value & 0xFFFF_FFFF) as u32);

        let mut config = self.inner.config.read();
        config.set_accumulator_config(true);
        self.inner.config.write(config);
        self.inner
            .comparator_value_high
            .write((value >> 32) as u32);
    }

    /// Set Edge Trigger.
    pub fn set_edge_trigger(&mut self) {
        let mut config = self.inner.config.read();
        config.set_interrupt_type(false);
        self.inner.config.write(config);
    }

    /// Set Level Trigger.
    pub fn set_level_trigger(&mut self) {
        let mut config = self.inner.config.read();
        config.set_interrupt_type(true);
        self.inner.config.write(config);
    }

    /// Set the timer in One Shot mode.
    pub fn set_one_shot_mode(&mut self) {
        let mut config = self.inner.config.read();
        config.set_timer_type(false);
        self.inner.config.write(config);
    }

    /// Set the timer in Periodic mode.
    ///
    /// # Note
    ///
    /// The timer must support periodic mode.
    pub fn set_periodic_mode(&mut self) {
        let mut config = self.inner.config.read();
        config.set_timer_type(true);
        self.inner.config.write(config);
    }

    /// Enable interrupt.
    pub fn enable_interrupt(&mut self) {
        let mut config = self.inner.config.read();
        config.set_interrupt_enable(true);
        self.inner.config.write(config);
    }

    /// Disable interrupt.
    pub fn disable_interrupt(&mut self) {
        let mut config = self.inner.config.read();
        config.set_interrupt_enable(false);
        self.inner.config.write(config);
    }

    /// Determine if the interrupt is enabled.
    pub fn has_interrupt_enabled(&self) -> bool {
        self.inner.config.read().interrupt_enable()
    }
}

impl Hpet {
    /// The minimal precision we are going to use for the HPET in femtosecond.
    /// 
    // TODO: Switch to a lower update frequency in HPET 
    // BODY: By specs, the minimal frequency of the HPET is 10Mhz, so our minimal precision can be 100 nanoseconds but for now it's 1 milliseconds.
    // BODY: For that to be possible, we need to take care of the sleep_thread logic and usage in the userland drivers (e.g: AHCI).
    const PRECISION_FS: u64 = 1_000_000 * 1_000_000;

    /// Create a new HPET device instance from MMIO registers.
    ///
    /// # Safety
    ///
    /// We take ownership of inner, it should be a unique pointer.
    unsafe fn new(inner: *mut HpetRegister) -> Self {
        debug!("Creating new HPET with registers at {:p}", inner);
        let mut res = Hpet {
            inner: inner.as_mut().unwrap(),
            timer_count: 1,
            period: 0,
        };
        res.timer_count = res.inner.identifier.read().timer_count_minus_one() + 1;
        res.period = res.inner.period.read();

        res
    }

    /// Return true if the device supports "legacy mapping".
    pub fn has_legacy_mapping(&self) -> bool {
        self.inner.identifier.read().legacy_rt_capability()
    }

    /// Return the period of the HPET device.
    pub fn get_period(&self) -> u32 {
        self.period
    }

    /// Return the frequency of the HPET device.
    pub fn get_frequency(&self) -> u64 {
        1000000000000000 / u64::from(self.get_period())
    }

    /// Enable the "legacy mapping".
    pub fn enable_legacy_mapping(&mut self) {
        let mut general_configuration = self.inner.general_configuration.read();
        general_configuration.set_legacy_rt_config(true);
        self.inner
            .general_configuration
            .write(general_configuration)
    }

    /// Disable the "legacy mapping".
    pub fn disable_legacy_mapping(&mut self) {
        let mut general_configuration = self.inner.general_configuration.read();
        general_configuration.set_legacy_rt_config(false);
        self.inner
            .general_configuration
            .write(general_configuration)
    }

    /// Check "legacy mapping" status.
    pub fn is_legacy_mapping_enabled(&self) -> bool {
        let general_configuration = self.inner.general_configuration.read();
        general_configuration.legacy_rt_config()
    }

    /// Enable HPET (main timer running, and timer interrupts allowed).
    pub fn enable(&mut self) {
        let mut general_configuration = self.inner.general_configuration.read();
        general_configuration.set_enable_config(true);
        self.inner
            .general_configuration
            .write(general_configuration)
    }

    /// Set HPET main counter value.
    pub fn set_main_counter_value(&mut self, value: u64) {
        self.inner
            .main_counter_value
            .write(value)
    }

    /// Get HPET main counter value.
    pub fn get_main_counter_value(&self) -> u64 {
        self.inner.main_counter_value.read()
    }

    /// Disable HPET (main timer halted, and timer interrupts disabled).
    pub fn disable(&mut self) {
        let mut general_configuration = self.inner.general_configuration.read();
        general_configuration.set_enable_config(false);

        self.inner
            .general_configuration
            .write(general_configuration)
    }

    /// Check HPET status.
    pub fn is_enabled(&self) -> bool {
        let general_configuration = self.inner.general_configuration.read();
        general_configuration.enable_config()
    }

    /// Get a timer at the given index.
    pub fn get_timer(&self, index: u32) -> Option<HpetTimer> {
        if index >= self.timer_count {
            return None;
        }
        let mmio_base_address = self.inner as *const _ as usize;

        let timer_address = mmio_base_address + 0x100 + (0x20 * index) as usize;
        unsafe {
            // Safety: Technically unsound. We need to prevent the user from borrowing the same HpetTimer twice.
            Some(HpetTimer::new(timer_address as *mut HpetTimerRegister))
        }
    }
}

impl timer::TimerDriver for Hpet {
    /// Function in charge of setting up a new one shot timer.
    fn set_oneshot_timer(&mut self, interval: u64) {
        let mut main_timer = self.get_timer(0).expect("HPET main timer isn't present! THIS SHOULDN'T HAPPEN BY SPEC");

        main_timer.disable_interrupt();

        // IO-APIC expects edge triggering by default.
        main_timer.set_edge_trigger();
        main_timer.set_one_shot_mode();
        main_timer.enable_interrupt();

        // TODO: Use IRQ2 for HPET.
        // BODY: Idealy, HPET should be using IRQ2 (which seems to be generally
        // BODY: wired properly). Unfortunately, qemu has an unfortunate bug where
        // BODY: interrupts for IRQ2 gets ignored.
        // BODY: 
        // BODY: As a workaround, we currently use IRQ16 as the timer IRQ. This is
        // BODY: not very portable - but it'll do until we have a proper IRQ
        // BODY: allocation scheme.
        // BODY: 
        // BODY: Upstream bug: https://bugs.launchpad.net/qemu/+bug/1834051
        // Route the timer to the IRQ 16. IRQ 2 is broken, and IRQ 0 is not
        // supported.
        main_timer.set_interrupt_route(16);

        main_timer.set_comparator_value(interval);
        crate::i386::interrupt::unmask(16);
    }

    /// Return the target tick to wait on.
    fn get_target_ticks(&self, ticks: u64) -> u64 {
        self.get_main_counter_value() + ticks
    }

    fn is_after_or_equal_main_ticks(&self, target_ticks: u64) -> bool {
        target_ticks >= self.get_main_counter_value()
    }

    /// Convert the given nanoseconds to timer ticks.
    #[inline]
    fn convert_ns_to_ticks(&self, ns: u64) -> u64 {
        let minmial_tick_value = Self::PRECISION_FS / u64::from(self.get_period());
        let computed_ticks_value = (ns * 1_000_000) / u64::from(self.get_period());

        core::cmp::max(minmial_tick_value, computed_ticks_value)
    }
}

assert_eq_size!(HpetRegister, [u8; 0x100]);

/// The instance of the HPET device we are using.
static mut HPET_INSTANCE: Option<Hpet> = None;

/// Stores the instance of Sunrise's timer driver.
pub static TIMER_DRIVER: Once<SpinLockIRQ<Hpet>> = Once::new();

/// Try to initialize the HPET in legacy mode.
///
/// # Safety
///
/// Should only be called once. The Hpet registers should not be aliased - we take
/// ownership of them.
pub unsafe fn init(hpet: &acpi::Hpet) -> bool {
    let physical_mem = PhysicalMemRegion::on_fixed_mmio(
        PhysicalAddress(hpet.base_address.address as usize),
        PAGE_SIZE,
    )
    .unwrap();
    let virtual_address = paging::kernel_memory::get_kernel_memory().map_phys_region(
        physical_mem,
        MappingAccessRights::READABLE | MappingAccessRights::WRITABLE,
    );
    let hpet_mmio = virtual_address.addr() as *mut HpetRegister;
    let mut hpet_instance = Hpet::new(hpet_mmio);

    // First disable the hpet if it's running.
    if hpet_instance.is_enabled() {
        hpet_instance.disable();
        hpet_instance.set_main_counter_value(0);
    }

    // Clear the interrupt state
    hpet_instance.enable();

    // Set the global instance
    TIMER_DRIVER.call_once(|| {
        SpinLockIRQ::new(hpet_instance)
    });

    true
}
