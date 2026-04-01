/// Initialize the RISC-V vDSO getcpu by setting CPU→node mapping.
pub fn init_vdso_getcpu(cpu_id: u32, node_id: u32) {
    crate::riscv64::vdso_data::set_cpu_node(cpu_id, node_id);
}
