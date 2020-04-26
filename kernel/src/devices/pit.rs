//! Programmable Interval Timer
//!
//! ### channels
//!
//! There are 3 channels :
//! * channel 0, wired to irq0.
//!   We use this one in rate generator mode, to keep track of the time
//!
//! * channel 1, "unusable, and may not even exist" ... whoah
//!
//! * channel 2, wired to pc speaker.
//!   We use this one in "one shot" mode to implement a simple wait function.
//!   Output is ANDed with a gate controlled by port 0x61 bit #1 before going to the pc speaker,
//!   we use this to enable/disable the speaker.
//    TODO
//!   However the channel can only track one countdown at a time,
//!   so we have to switch to channel 0 timers when we want to wait
//!   as soon as we have interruptions working
//!
//! ### operating modes
//!
//! Each channel can operate in different modes. The ones we use are:
//! * Mode 0 - Countdown (poorly named "Interrupt on Terminal Count").
//!   Used on channel 2 to create countdowns.
//!   Set the reset value, countdowns starts.
//!   When countdown goes to 0, OUT goes HIGH, and stays high.
//!
//! * Mode 2 - Rate generator.
//!   Used on channel 0 to create recurring irqs.
//!   Set the reset value. Countdown starts.
//!   When countdown goes to 0, OUT goes LOW for 1 clock cycle, and HIGH again,
//!   and countdown restarts.
//!
//! ### commands
//!
//! Pit commands are sent on port 0x43.
//! See [OSDEV](https://wiki.osdev.org/Programmable_Interval_Timer#I.2FO_Ports)
//!
//! To write channel reload values we always use the Access mode "lobyte/hibyte"
//!
//! ### port 0x61
//!
//! The PIT makes great use of the IO port 0x61 :
//! * bit #0 is channel 2 GATE control
//! * bit #1 is SPKR control
//! * bit #4 is channel 1 OUT status
//! * bit #5 is channel 2 OUT status
//!
//! ## References
//!
//! * [OSDEV](https://wiki.osdev.org/Programmable_Interval_Timer)
//! * [this very good ppt](https://www.cs.usfca.edu/~cruse/cs630f08/lesson15.ppt)
//!

use crate::sync::SpinLock;
use crate::io::Io;
use crate::i386::pio::Pio;

/// The oscillator frequency when not divided, in hertz.
const OSCILLATOR_FREQ: usize = 1193182;

/// The frequency of channel 0 irqs, in hertz.
/// One every 10 millisecond.
pub const CHAN_0_FREQUENCY: usize = 100;

/// The channel 0 reset value
const CHAN_0_DIVISOR: u16 = (OSCILLATOR_FREQ / CHAN_0_FREQUENCY) as u16;

lazy_static! {
    /// The mutex wrapping the ports
    static ref PIT_PORTS: SpinLock<PITPorts> = SpinLock::new(PITPorts {
        /// Port 0x40, PIT's Channel 0.
        port_chan_0: Pio::new(0x40),
        /// Port 0x42, PIT's Channel 2.
        port_chan_2: Pio::new(0x42),
        /// Port 0x43, PIT's Mode/Command register.
        port_cmd:    Pio::new(0x43),
        /// Port 0x61, reads as a [Port61Flags].
        port_61:     Pio::new(0x61)
    });
}

/// Used internally to select which channel to apply operations to.
#[derive(Debug, Clone, Copy)]
enum ChannelSelector {
    /// Operation should apply to Channel 0.
    Channel0,
    /// Operation should apply to Channel 2.
    Channel2
}

bitflags! {
    /// The port 0x61 flags we use.
    struct Port61Flags: u8 {
        const SPKR_CONTROL = 1 << 1;
        const OUT2_STATUS  = 1 << 5;

        // Other flags so bitflags can work
        const GATE_2       = 1 << 0;
        const OUT1_STATUS  = 1 << 4;
        const OTHER_2 = 1 << 2;
        const OTHER_3 = 1 << 3;
        const OTHER_6 = 1 << 6;
        const OTHER_7 = 1 << 7;
    }
}

/// We put the PIT ports in a structure to have them under a single mutex
#[allow(clippy::missing_docs_in_private_items)]
struct PITPorts {
    port_chan_0: Pio<u8>,
    port_chan_2: Pio<u8>,
    port_cmd:    Pio<u8>,
    port_61:     Pio<u8>
}

impl PITPorts {
    /// Writes a reload value in lobyte/hibyte access mode
    fn write_reload_value(&mut self, channel_selector: ChannelSelector, value: u16) {
        let port = match channel_selector {
            ChannelSelector::Channel0 => &mut self.port_chan_0,
            ChannelSelector::Channel2 => &mut self.port_chan_2
        };
        let lo: u8 = (value & 0xFF) as u8;
        let hi: u8 = (value >> 8) as u8;
        port.write(lo);
        port.write(hi);
    }
}

/// Prevent the PIT from generating interrupts.
pub unsafe fn disable() {
    let mut ports = PIT_PORTS.lock();
    ports.port_cmd.write(0b00110010); // channel 0, lobyte/hibyte, one-shot
    ports.write_reload_value(ChannelSelector::Channel0, 1);
}
