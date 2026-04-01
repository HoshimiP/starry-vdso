use crate::vdso_time_data::VdsoTimeData;

const CPU_TO_NODE_STRIDE: usize = 64;
const MAX_CPUS: usize = 512;
const CPU_TO_NODE_SIZE: usize = MAX_CPUS * CPU_TO_NODE_STRIDE;

#[repr(C)]
pub struct VdsoData {
    pub time_data: VdsoTimeData,              // ~4KB, offset 0
    pub timens_data: [u8; 4096],             // offset 4KB
    pub rng_data: [u8; 4096],                // offset 8KB
    pub cpu_to_node: [u8; CPU_TO_NODE_SIZE],// offset 12KB, CPU→node mapping
}

impl Default for VdsoData {
    fn default() -> Self {
        Self::new()
    }
}

impl VdsoData {
    pub const fn new() -> Self {
        Self {
            time_data: VdsoTimeData::new(),
            timens_data: [0u8; 4096],
            rng_data: [0u8; 4096],
            cpu_to_node: [0u8; CPU_TO_NODE_SIZE],
        }
    }

    pub fn time_update(&mut self) {
        self.time_data.update();
    }
}

pub fn set_cpu_node(cpu_id: u32, node_id: u32) {
    let offset = (cpu_id as usize) * CPU_TO_NODE_STRIDE;
    if offset + 4 <= CPU_TO_NODE_SIZE {
        let node_bytes = node_id.to_le_bytes();
        let slice = unsafe { &mut crate::vdso::VDSO_DATA.cpu_to_node[offset..offset + 4] };
        slice.copy_from_slice(&node_bytes);
        log::info!("Set CPU {cpu_id} -> node {node_id}");
    } else {
        log::warn!("CPU ID {cpu_id} out of range for cpu_to_node map");
    }
}
