//! Arch-independent traits for architectures that implement paging as a hierarchy of page tables

// what the architecture code still has define
use super::arch::{PAGE_SIZE, ENTRY_COUNT, Entry, EntryFlags};
use super::lands::{KernelLand, UserLand, RecursiveTablesLand, VirtualSpaceLand};
use super::MappingFlags;

use mem::{VirtualAddress, PhysicalAddress};
use frame_allocator::{PhysicalMemRegion, FrameAllocatorTrait};
use utils::align_up_checked;
use core::ops::IndexMut;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::iter::{Flatten, Iterator, Peekable};
use core::slice::Iter;

/// A hierarchical paging is composed of entries. An entry can be in the following states:
///
/// - Available, aka unused
/// - Present, which is used and has a backing physical address
/// - Guarded, which is reserved and will cause a pagefault on use.
///
/// PageState is generic over various kind of Present states, similar to the
/// Option type.
#[derive(Debug)]
pub enum PageState<T> {
    Available,
    Guarded,
    Present(T)
}

impl<T> PageState<T> {
    /// Move the value T out of the PageState<T> if it is Present(T).
    ///
    /// # Panics
    ///
    /// Panics if the self value isn't Present.
    pub fn unwrap(self) -> T {
        match self {
            PageState::Present(t) => t,
            _ => panic!("Table was not present")
        }
    }

    /// Maps a PageState<T> to PageState<U> by applying a function to a
    /// contained value.
    pub fn map<U, F>(self, f: F) -> PageState<U>
        where F: FnOnce(T) -> U {
        match self {
            PageState::Present(t) => PageState::Present(f(t)),
            PageState::Guarded => PageState::Guarded,
            PageState::Available => PageState::Available
        }
    }

    /// Turns the PageState into an Option, setting both Guarded and Available
    /// state to None, and Present(t) state to Some(t).
    pub fn as_option(&self) -> Option<&T> {
        match *self {
            PageState::Present(ref t) => Some(t),
            PageState::Guarded => None,
            PageState::Available => None,
        }
    }
}

/// A hierarchical paging is composed of entries. All entries implements the following trait
pub trait HierarchicalEntry {

    /// An entry comports some flags. They are often represented by a structure.
    type EntryFlagsType: From<MappingFlags>;

    /// Is the entry unused ?
    fn is_unused(&self) -> bool;

    /// Clear the entry
    fn set_unused(&mut self) -> PageState<PhysicalAddress>;

    /// Is the entry a page guard ?
    fn is_guard(&self) -> bool;

    /// Get the current entry flags
    fn flags(&self) -> Self::EntryFlagsType;

    /// Get the associated physical address, if available
    fn pointed_frame(&self) -> PageState<PhysicalAddress>;

    /// Sets the entry
    fn set(&mut self, frame: PhysicalAddress, flags: Self::EntryFlagsType);

    /// Make this entry a page guard
    fn set_guard(&mut self);
}

/// A hierarchical paging is composed of tables. All tables must implement the following trait
/// A table of entries, either the top-level directory or one of the page tables.
/// A table is a parent table if its child are also tables, instead of regular pages.
pub trait HierarchicalTable {

    /// The Entry our table has
    type EntryType : HierarchicalEntry;
    /// A Flusher that should be called on table modifications
    type CacheFlusherType : PagingCacheFlusher;
    /// If we're a parent table, the type of our child tables.
    /// If we're not a parent, this type will never be used and you can set it to Self.
    type ChildTableType : HierarchicalTable;

    /// gets the raw array of entries
    fn entries(&mut self) -> &mut [Self::EntryType];

    /// zero out the whole table
    fn zero(&mut self) {
        for entry in self.entries().iter_mut() {
            entry.set_unused();
        }
        Self::CacheFlusherType::flush_whole_cache();
    }

    /// Makes all entries guarded
    fn guard_all_entries(&mut self) {
        for entry in &mut self.entries().iter_mut() {
            entry.set_guard();
        }
        Self::CacheFlusherType::flush_whole_cache();
    }

    /// Creates a mapping on the nth entry of a table
    fn map_nth_entry(&mut self, entry: usize, paddr: PhysicalAddress, flags: <Self::EntryType as HierarchicalEntry>::EntryFlagsType) {
        self.entries()[entry].set(paddr, flags);
        Self::CacheFlusherType::flush_whole_cache();
    }

    /// Marks the nth entry as guard page
    fn guard_nth_entry(&mut self, entry: usize) {
        self.entries()[entry].set_guard();
        Self::CacheFlusherType::flush_whole_cache();
    }

    /// Marks the nth entry as guard page
    fn unmap_nth_entry(&mut self, entry: usize) {
        self.entries()[entry].set_unused();
        Self::CacheFlusherType::flush_whole_cache();
    }

    /// Called to check if this table's entries should be treated as pointers to child tables.
    /// Level 0 = simple table, level 1 = parent of simple tables, level 2 = parent of parent of simple tables, ...
    fn table_level() -> usize;

    /// the size an entry in this table spans in virtual memory.
    /// should be something like PAGE_SIZE * (ENTRY_COUNT ^ table level)
    fn entry_vm_size() -> usize {
        ENTRY_COUNT.pow(Self::table_level() as u32) * PAGE_SIZE
    }

    /// Gets a reference to a child page table.
    ///
    /// # Panics
    ///
    /// Should panic if called on a table which isn't a parent table.
    fn get_child_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, Self::ChildTableType>>;

    /// Allocates a child page table, zero it and add an entry pointing to it.
    ///
    /// # Panics
    ///
    /// Should panic if called on a table which isn't a parent table.
    /// Should panic if entry was not available.
    fn create_child_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, Self::ChildTableType>;

    /// Gets the child page table at given index, or creates it if it does not exist
    ///
    /// # Panics
    ///
    /// Should panic if called on a table which isn't a parent table.
    fn get_child_table_or_create<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, Self::ChildTableType>> {
        assert!(Self::table_level() >= 1, "get_child_table_or_create() called on non-parent table");
        match self.entries()[index].pointed_frame() {
            PageState::Present(_) => self.get_child_table(index),
            PageState::Available => PageState::Present(self.create_child_table(index)),
            PageState::Guarded => PageState::Guarded
        }
    }
}

/// Most implementations of paging have are accelerated with a cache that must be manually updated
/// when changes to the page tables are made. The way we specify which part of the cache gets invalidated
/// is arch-specific. We only provide the declaration for a flusher that our page tables can use.
///
//TODO
/// Our implementation only enables flushing the whole cache for every operation, which is the only
/// available way on i386, but should be more fine-grained for other architectures
pub trait PagingCacheFlusher {
    /// Flushes the whole cache.
    fn flush_whole_cache();
}

/// Flusher that doesn't flush.
///
/// When passing this struct the TLB will **not** be flushed. Used by Inactive/PagingOff page tables,
/// and DynamicHierarchy
pub struct NoFlush;
impl PagingCacheFlusher for NoFlush { fn flush_whole_cache() { /* do nothing */ } }

/// This is just a wrapper for a pointer to a table.
/// It enables us to do handle when it is dropped
pub struct SmartHierarchicalTable<'a, T: HierarchicalTable + 'a>(*mut T, PhantomData<&'a T>);

impl<'a, T: HierarchicalTable> SmartHierarchicalTable<'a, T> {
    pub fn new(inner: *mut T) -> SmartHierarchicalTable<'a, T> {
        SmartHierarchicalTable(inner, PhantomData)
    }
}

impl<'a, T: HierarchicalTable> Deref for SmartHierarchicalTable<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe {
            self.0.as_ref().unwrap()
        }
    }
}

impl<'a, T: HierarchicalTable> DerefMut for SmartHierarchicalTable<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe {
            self.0.as_mut().unwrap()
        }
    }
}

impl<'a, T: HierarchicalTable> Drop for SmartHierarchicalTable<'a, T> {
    fn drop(&mut self) {
        unsafe {
            ::core::ptr::drop_in_place(self.0);
        }
    }
}

/// A trait operating on a whole hierarchy of tables.
///
/// Implementer only has to provide a function to map the top level table,
/// and the trait does the rest.
///
/// Thanks to this we can have the same api for every kind of page tables, the only difference is
/// the way we access the page directory :
///
/// * an ActiveHierarchy will want to use recursive mapping
/// * an InactiveHierarchy will want to temporarily map the top level page
/// * a  PagingOffHierarchy will point to physical memory
pub trait TableHierarchy {
    type TopLevelTableType : HierarchicalTable;

    /// Gets a reference to the top level table, either through recursive mapping,
    /// or by temporarily mapping it in the currently active page tables.
    fn get_top_level_table<'a>(&'a mut self) -> SmartHierarchicalTable<'a, Self::TopLevelTableType>;

    /// Creates a mapping in the page tables with the given flags.
    ///
    /// The physical frames to map are passed as an iterator that yields physical addresses.
    /// The mapping begins at `start_address`, and advances by PAGE_SIZE steps, consuming
    /// `frames_iterator` every time.
    /// When `frames_iterator` is depleted, the mapping stops.
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    /// Panics if any encountered entry was already in use
    fn map_to_from_iterator<I>(&mut self,
                               frames_iterator: I,
                               start_address: VirtualAddress,
                               flags: MappingFlags)
    where I: Iterator<Item=PhysicalAddress>
    {
        assert_eq!(start_address.addr() % PAGE_SIZE, 0, "Address is not page aligned");

        /// Delay work to child tables, and map it ourselves when we have no more children.
        /// Panics if any entry was already in use
        fn rec_map_to<T, I>(table: &mut SmartHierarchicalTable<T>,
                            frames_iterator: &mut Peekable<I>,
                            start_address: usize,
                            flags: MappingFlags)
        where T: HierarchicalTable,
              I: Iterator<Item=PhysicalAddress>
        {
            let entry_offset : usize = start_address / T::entry_vm_size();
            assert!(entry_offset < ENTRY_COUNT, "rec_map_to computed an entry offset > ENTRY_COUNT,
                                                is your arch-specific paging valid ?");
            // our first child table will have to map to it's nth entry
            let mut child_start_address = start_address % T::entry_vm_size();

            for index in entry_offset..ENTRY_COUNT {
                if frames_iterator.peek().is_none() { return; }
                match (T::table_level(), table.entries()[index].pointed_frame()) {
                    (0, PageState::Available) => {
                        // we're a simple table, map it ourselves.
                        table.map_nth_entry(index, frames_iterator.next().unwrap(),
                                            <T::EntryType as HierarchicalEntry>::EntryFlagsType::from(flags));
                    },
                    (level, PageState::Available) | (level, PageState::Present(_)) if level > 0 => {
                        // we're a parent table, delay work to our childs !
                        let mut child_table = table.get_child_table_or_create(index).unwrap();
                        rec_map_to(&mut child_table, frames_iterator, child_start_address, flags);
                        // all other child tables will start mapping from their first entry
                        child_start_address = 0;
                    },
                    _ => { panic!("rec_map_to was asked to map a non-available entry"); }
                }
            }
        }

        return rec_map_to(&mut self.get_top_level_table(),
                          &mut frames_iterator.peekable(),
                          start_address.addr(), flags);
    }

    /// Creates a span of guard pages
    ///
    /// This function will avoid creating child tables filled only with guarded entry,
    /// and instead guard a single entry in the parent. This is called a HUGE guard.
    ///
    /// # Panics
    ///
    /// Panics if any encountered entry was already in use
    /// Panics if address is not page-aligned.
    /// Panics if length is not page-aligned.
    fn guard(&mut self, address: VirtualAddress, mut length: usize) {
        assert_eq!(address.addr() % PAGE_SIZE, 0, "Guarding : address is not page aligned");
        assert_eq!(length         % PAGE_SIZE, 0, "Guarding : length is not page aligned");

        /// Delay work to child tables, and guard it ourselves when we have no more children.
        /// Panics if any entry was already in use
        fn rec_guard<T>(table : &mut SmartHierarchicalTable<T>,
                        start_address: usize,
                        length: &mut usize)
        where T: HierarchicalTable
        {
            let start_entry: usize = start_address / T::entry_vm_size();
            assert!(start_entry < ENTRY_COUNT, "rec_guard computed an entry offset > ENTRY_COUNT,
                                                is your arch-specific paging valid ?");
            let mut child_start_address = start_address % T::entry_vm_size();
            for entry_index in start_entry..ENTRY_COUNT {
                if *length == 0 { return; }
                match (T::table_level(), table.entries()[entry_index].pointed_frame()) {
                    (_, PageState::Guarded) => panic!("rec_guard encountered an already guarded entry"),
                    (0, PageState::Present(_)) => panic!("rec_guard was asked to guard a non-available entry"),
                    (_, PageState::Present(_)) => {
                        // delay work to our child
                        let mut child_table = table.get_child_table(entry_index).unwrap();
                        rec_guard(&mut child_table, child_start_address, length);
                    },
                    (_, PageState::Available) if *length >= T::entry_vm_size() && child_start_address == 0 => {
                        // map a (huge ?) guard here
                        table.guard_nth_entry(entry_index);
                        *length -= T::entry_vm_size();
                    },
                    (_, PageState::Available) => {
                        // length to map is smaller than our granularity, we must be a parent table
                        assert!(T::table_level() > 0, "rec_guard encountered an error,
                                                           is your arch-specific paging valid ?");
                        // create a child table, and recurse into it.
                        let mut child_table = table.create_child_table(entry_index);
                        rec_guard(&mut child_table, child_start_address, length);
                    }
                }
                // all other children will start guarding from their first entry
                child_start_address = 0;
            }
        }

        return rec_guard(&mut self.get_top_level_table(), address.addr(), &mut length);
    }

    /// Unmaps a range of virtual address.
    /// On every frames mapped by a level 0 table, the closure passed as parameter will be called
    /// after having deleted the entry.
    /// If unmap encounters a guard page, it is unmapped, and the closure is not called.
    /// If unmap encounters a HUGE guard page, it decides if it must split it and might
    /// create a child table which is only partly guarded.
    /// If unmap encounters a non-mapped entry, it panics, as this is probably a bug.
    ///
    /// If a table is left empty after an unmap, it is never deallocated, and left as is.
    ///
    /// # Panics
    ///
    /// Panics if encounters any entry that was not mapped.
    /// Panics if address is not page-aligned.
    /// Panics if length  is not page-aligned.
    fn unmap<C>(&mut self, address: VirtualAddress, mut length: usize, mut callback: C)
    where C: FnMut(PhysicalAddress)
    {
        assert_eq!(address.addr() % PAGE_SIZE, 0, "Address is not page aligned");
        assert_eq!(length         % PAGE_SIZE, 0, "Length is not page aligned");

        /// Delay work to child tables, and unmap it ourselves when we have no more children.
        fn rec_unmap<T, C>(table: &mut SmartHierarchicalTable<T>,
                        start_address: usize,
                        length: &mut usize,
                        callback: &mut C)
        where T: HierarchicalTable,
              C: FnMut(PhysicalAddress)
        {
            let start_offset: usize = start_address / T::entry_vm_size();
            assert!(start_offset < ENTRY_COUNT, "rec_unmap computed an entry offset > ENTRY_COUNT,
                                                 is your arch-specific paging valid ?");
            let mut child_start_address = start_address % T::entry_vm_size();

            for entry_index in start_offset..ENTRY_COUNT {
                if *length == 0 { return; }
                match (T::table_level(), table.entries()[entry_index].pointed_frame()) {
                    (_, PageState::Available) => panic!("unmap encountered a non-mapped entry, is this a bug ?"),
                    (0, PageState::Present(paddr)) => {
                        // unmap the entry and call callback
                        table.unmap_nth_entry(entry_index);
                        callback(paddr);
                        *length -= T::entry_vm_size();
                    },
                    (_, PageState::Present(_)) => {
                        // recurse into child table
                        let mut child_table = table.get_child_table(entry_index).unwrap();
                        rec_unmap(&mut child_table, child_start_address, length, callback)
                    },
                    (_, PageState::Guarded) if *length >= T::entry_vm_size() => {
                        // make the (huge ?) guard available
                        table.unmap_nth_entry(entry_index);
                        *length -= T::entry_vm_size();
                    },
                    (_, PageState::Guarded) => {
                        // we have to split the huge guard
                        table.unmap_nth_entry(entry_index);
                        let mut child_table = table.create_child_table(entry_index);
                        child_table.guard_all_entries();
                        rec_unmap(&mut child_table, child_start_address, length, callback)
                    }
                }
                // next child table will start on its first entry
                child_start_address = 0;
            }
        }

        rec_unmap(&mut self.get_top_level_table(), address.addr(), &mut length, &mut callback);
    }

    /// Iters in the page tables, applying closure on every mapping.
    /// On every entry, the closure will be called with its state and the length it maps.
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    /// Panics if length  is not page-aligned.
    fn for_every_entry<C>(&mut self, address: VirtualAddress, mut length: usize, mut callback: C)
    where C: FnMut(PageState<PhysicalAddress>, usize)
    {
        assert_eq!(address.addr() % PAGE_SIZE, 0, "Address is not page aligned");
        assert_eq!(length         % PAGE_SIZE, 0, "Length is not page aligned");

        /// Delay work to child tables, and iter it ourselves when we have no more children.
        fn rec_iter<T, C>(table: &mut SmartHierarchicalTable<T>,
                        start_address: usize,
                        length: &mut usize,
                        callback: &mut C)
        where T: HierarchicalTable,
              C: FnMut(PageState<PhysicalAddress>, usize)
        {
            let start_offset: usize = start_address / T::entry_vm_size();
            assert!(start_offset < ENTRY_COUNT, "rec_iter computed an entry offset > ENTRY_COUNT,
                                                 is your arch-specific paging valid ?");
            let mut child_start_address = start_address % T::entry_vm_size();

            for entry_index in start_offset..ENTRY_COUNT {
                if *length == 0 { return; }
                match (T::table_level(), table.entries()[entry_index].pointed_frame()) {
                    (level, PageState::Present(_)) if level != 0 => {
                        // recurse into child table
                        let mut child_table = table.get_child_table(entry_index).unwrap();
                        rec_iter(&mut child_table, child_start_address, length, callback)
                    },
                    (_, state) => {
                        callback(state, T::entry_vm_size());
                        *length = length.saturating_sub(T::entry_vm_size());
                    },
                }
                // next child table will start on its first entry
                child_start_address = 0;
            }
        }

        rec_iter(&mut self.get_top_level_table(), address.addr(), &mut length, &mut callback);
    }

    /// Finds a virtual space hole that is at least length long, between start_addr and end_addr.
    ///
    /// # Panics
    ///
    /// Panics if start_addr is not page-aligned.
    /// Panics if     length is not page-aligned.
    /// Panics if  alignment is not page-aligned.
    /// Panics if start_addr > end_addr.
    /// Panics if length is zero.
    fn find_available_virtual_space_aligned(&mut self,
                                            length: usize,
                                            start_addr: VirtualAddress,
                                            end_addr: VirtualAddress,
                                            alignment: usize
                                        ) -> Option<VirtualAddress> {
        assert_eq!(start_addr.addr() % PAGE_SIZE, 0, "start_addr is not page aligned");
        assert_eq!(length            % PAGE_SIZE, 0, "length is not page aligned");
        assert_eq!(alignment         % PAGE_SIZE, 0, "alignment is not page aligned");
        assert!(start_addr <= end_addr, "start_addr > end_addr");
        assert!(length > 0, "length == 0");

        if length > end_addr.addr() - start_addr.addr() {
            // search region is to small to begin with
            return None
        }

        struct Hole { start_addr: usize, len: usize };

        let mut hole; // the hole we are currently considering

        if let Some(first_aligned_addr) = align_up_checked(start_addr.addr(), alignment) {
            hole = Hole { start_addr: first_aligned_addr, len: 0 }
        } else {
            return None; // there was no aligned address between start_addr and end_addr
        }

        /// Delay work to child tables.
        fn rec_find<T>(table: &mut SmartHierarchicalTable<T>,
                       table_addr: usize,
                       hole: &mut Hole,
                       desired_length: usize,
                       start_addr: usize,
                       end_addr: usize,
                       alignment: usize)
            where T: HierarchicalTable
        {
            let mut next_entry_index;
            while {
                next_entry_index = (hole.start_addr.saturating_add(hole.len) - table_addr) / T::entry_vm_size();

                next_entry_index < ENTRY_COUNT // does this still concern my table ?
                && hole.len < desired_length // are we done yet ?
                && hole.start_addr.checked_add(desired_length) // is length still obtainable ?
                    .filter(|minimun_end| *minimun_end <= end_addr).is_some() }
            {
                match (T::table_level(), table.entries()[next_entry_index].pointed_frame()) {
                    (_, PageState::Available) => {
                        // hole is still growing
                        hole.len += T::entry_vm_size();
                    },
                    (0, PageState::Present(_)) | (_, PageState::Guarded) => {
                        // hole was not big enough :(
                        // start a new hole on the next aligned address
                        hole.len = 0;
                        hole.start_addr = hole.start_addr.saturating_add(alignment);
                    },
                    (_, PageState::Present(_)) => {
                        // we must look into child table
                        let mut child_table = table.get_child_table(next_entry_index).unwrap();
                        let child_table_addr = table_addr + next_entry_index * T::entry_vm_size();
                        rec_find(&mut child_table, child_table_addr, hole, desired_length, start_addr, end_addr, alignment)
                    }
                }
            }
        }

        rec_find(&mut self.get_top_level_table(),
                 0x00000000,
                 &mut hole,
                 length,
                 start_addr.addr(),
                 end_addr.addr(),
                 alignment
        );

        return if hole.len >= length {
            Some(VirtualAddress(hole.start_addr))
        } else {
            None
        }
    }
}

/// A trait implemented by innactive table hierarchies.
/// Enables creating a
pub trait InactiveHierarchyTrait : TableHierarchy {
    /// Creates a hierarchy. Allocates at least a top level directory,
    /// make all its entries unmapped, and make its last entry recursive.
    fn new() -> Self;

    /// Switches to this hierarchy,
    ///
    /// Since all process are supposed to have the same view of kernelspace,
    /// this function will copy the part of the active directory that is mapping kernel space tables
    /// to the directory being switched to, and then performs the switch
    fn switch_to(&mut self);

    /// De-allocates all physical memory used by tables of this hierarchy,
    /// by iterating in RecursiveTablesLand, and freeing every entry.
    ///
    /// Does not unmap UserLand and KernelLand memory,
    /// this should be done before calling this function, otherwise they will be leaked.
    ///
    /// This might be called by the Drop of the struct it's implemented on.
    unsafe fn destroy(&mut self) {
        self.unmap(RecursiveTablesLand::start_addr(), RecursiveTablesLand::length(), |paddr| {
            unsafe {
                // safe because they were existing frames, and not tracked by any one except the page tables.
                PhysicalMemRegion::reconstruct(paddr, PAGE_SIZE);
                // dropping the region deallocates it
            }
        });
    }

    /// Performs a shallow copy of the top level-directory section that maps KernelLand tables.
    ///
    /// Used when about to switch to a hierarchy, to update it before switching to it.
    fn copy_active_kernel_space(&mut self);

    /// Checks if this inactive hierarchy is actually the currently active one.
    ///
    /// Generally this means comparing the current MMU register pointer to top-level table with the
    /// address of the top-level table of this hierarchy.
    fn is_currently_active(&self) -> bool;

    /// Returns the currently active hierarchy as an inactive hierarchy.
    unsafe fn from_currently_active() -> Self;
}