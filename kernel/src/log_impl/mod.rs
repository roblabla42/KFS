//! A simple log implementation based on env_logger
#![allow(clippy::missing_docs_in_private_items)]
mod filter;

use log::{self, Log, Metadata, Record, LevelFilter};
use crate::devices::rs232::SerialLogger;
use core::fmt::Write;
use crate::i386::multiboot::get_boot_information;
use crate::sync::{SpinRwLock, Once};
use crate::scheduler;

struct Logger {
    filter: SpinRwLock<filter::Filter>
}

#[allow(unused_must_use)]
impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter.read().enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        use crate::devices::rs232::{SerialAttributes, SerialColor};
        let color = SerialAttributes::fg(match record.level() {
            log::Level::Error => SerialColor::Red,
            log::Level::Warn  => SerialColor::Yellow,
            log::Level::Info  => SerialColor::Green,
            log::Level::Debug => SerialColor::Cyan,
            log::Level::Trace => SerialColor::White,
        });
        if self.filter.read().matches(record) {
            if let Some(thread) = scheduler::try_get_current_thread() {
                writeln!(SerialLogger, "[{}{}{}] - {} - {} - {}", color, record.level(), SerialAttributes::default(), record.target(), thread.process.name, record.args());
            } else {
                writeln!(SerialLogger, "[{}{}{}] - {} - {}", color, record.level(), SerialAttributes::default(), record.target(), record.args());
            }
        }
    }

    fn flush(&self) {}
}

static LOGGER: Once<Logger> = Once::new();

/// Initializes the Logger in a heapless environment.
pub fn early_init() {
    let filter = filter::Builder::new()
        .filter(None, LevelFilter::Info)
        .build();
    log::set_logger(LOGGER.call_once(|| Logger { filter: SpinRwLock::new(filter) } ))
        .expect("log_impl::init to be called before logger is initialized");
    log::set_max_level(LevelFilter::Trace);
    info!("Logging enabled");
}

/// Reinitializes the logger using the cmdline. This requires the heap.
pub fn init() {
    let logger = LOGGER.r#try().expect("early_init to be called before init");
    let cmdline = get_boot_information().command_line().unwrap();
    let newfilter = filter::Builder::new().parse(cmdline.as_str()).build();
    *logger.filter.write() = newfilter;
}
