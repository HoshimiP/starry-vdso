use crate::vdso_ebpf_data::VdsoEbpfData;

#[repr(C)]
#[repr(align(4096))]
pub struct VdsoData {
    pub ebpf_data: VdsoEbpfData,
}

impl Default for VdsoData {
    fn default() -> Self {
        Self::new()
    }
}

impl VdsoData {
    pub const fn new() -> Self {
        Self {
            ebpf_data: VdsoEbpfData::new(),
        }
    }
}
