use core::cell::Cell;

use axplat::mem::{PhysAddr, VirtAddr};
use kernel_elf_parser::AuxType;
use starry_vdso::{
	config::VVAR_PAGES,
	vdso::load_vdso_data,
};

const PAGE_SIZE_4K: usize = 4096;

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub fn __TimeIf_current_ticks() -> u64 {
	1_000_000
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub fn __TimeIf_ticks_to_nanos(ticks: u64) -> u64 {
	ticks
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub fn __MemIf_virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
	let raw: usize = vaddr.into();
	raw.into()
}

#[test]
fn load_vdso() {
	let mut auxv = Vec::new();

	let f1_called = Cell::new(false);
	let f2_called = Cell::new(0usize);
	let f3_called = Cell::new(0usize);
	let seen_vvar_user_addr = Cell::new(0usize);

	let res = load_vdso_data(
		&mut auxv,
		|_, _, _| {
			f1_called.set(true);
			Ok(())
		},
		|vvar_user_addr, _| {
			f2_called.set(f2_called.get() + 1);
			seen_vvar_user_addr.set(vvar_user_addr);
			Ok(())
		},
		|_, _, _, _| {
			f3_called.set(f3_called.get() + 1);
			Ok(())
		},
	);

	assert!(res.is_ok());
	assert_eq!(f2_called.get(), 1);
	assert!(f1_called.get() || f3_called.get() > 0);

	let sysinfo = auxv
		.iter()
		.find(|e| e.get_type() == AuxType::SYSINFO_EHDR)
		.unwrap();
	let expected_vdso_addr = seen_vvar_user_addr.get() + VVAR_PAGES * PAGE_SIZE_4K;
	assert_eq!(sysinfo.value(), expected_vdso_addr);
}
