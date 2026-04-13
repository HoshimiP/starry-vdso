//! vDSO data management.
extern crate alloc;
extern crate log;
use alloc::{alloc::alloc_zeroed, vec::Vec};
use core::alloc::Layout;

use axerrno::{AxError, AxResult};
use axplat::{mem::virt_to_phys, time::monotonic_time_nanos};
use kernel_elf_parser::{AuxEntry, AuxType};
use log::{info, warn};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K};

use crate::vdso_ebpf_data::VdsoData;

#[repr(C, align(4096))]
struct AlignedVdsoData(pub VdsoData);

/// Global vDSO data instance. Keep it page-aligned so vVAR base math in kvdso
/// always lands on the data start even after struct layout growth.
#[unsafe(link_section = ".data")]
static mut VDSO_DATA: AlignedVdsoData =
    AlignedVdsoData(VdsoData::new());

#[inline]
fn vdso_data_ptr() -> *mut VdsoData {
    unsafe { core::ptr::addr_of_mut!(VDSO_DATA.0) }
}
/*
/// Initialize vDSO data
pub fn init_vdso_data() {
    unsafe {
        let data_ptr = core::ptr::addr_of_mut!(VDSO_DATA);
        (*data_ptr).time_update();
        info!("vDSO data initialized at {:#x}", data_ptr as usize);

        #[cfg(target_arch = "aarch64")]
        {
            crate::vdso_data::enable_cntvct_access();
            info!("vDSO CNTVCT access enabled");
        }
        #[cfg(target_arch = "x86_64")]
        {
            (*data_ptr).enable_pvclock();
        }
    }
}

/// Update vDSO data
pub fn update_vdso_data() {
    unsafe {
        let data_ptr = core::ptr::addr_of_mut!(VDSO_DATA);
        (*data_ptr).time_update();
    }
}
*/
/// Update the eBPF fast-path snapshot stored in vVAR.
pub fn update_ebpf_data(counts: &[u32; crate::vdso_ebpf_data::MAX_SYSNO]) {
    unsafe {
        let data_ptr = vdso_data_ptr();
        (*data_ptr).ebpf_data.update_counts(counts);
        let class_hist = classify_syscalls(counts);
        (*data_ptr)
            .sched_hint_data
            .update_from_class_hist(&class_hist, monotonic_time_nanos());
    }
}

/// Update scheduler runtime hints from non-eBPF kernel paths.
pub fn update_sched_runtime_data(
    tid: u64,
    task_state: u8,
    cpu_id: u8,
    is_idle: bool,
) {
    unsafe {
        let data_ptr = vdso_data_ptr();
        (*data_ptr).sched_hint_data.update_task_runtime(
            monotonic_time_nanos(),
            tid,
            task_state,
            cpu_id,
            is_idle,
        );
    }
}

fn classify_syscalls(
    counts: &[u32; crate::vdso_ebpf_data::MAX_SYSNO],
) -> [u32; crate::vdso_ebpf_data::SCHED_CLASS_MAX] {
    let mut class_hist = [0u32; crate::vdso_ebpf_data::SCHED_CLASS_MAX];
    for (sysno, cnt) in counts.iter().enumerate() {
        if *cnt == 0 {
            continue;
        }
        let class = match sysno as u32 {
            // read/pread/readv/recvfrom/recvmsg/epoll_wait/ppoll/select
            63 | 67 | 65 | 207 | 212 | 22 | 73 | 23 => crate::vdso_ebpf_data::SCHED_CLASS_IO_WAIT,
            // nanosleep/clock_nanosleep/sched_yield
            101 | 115 | 124 => crate::vdso_ebpf_data::SCHED_CLASS_SLEEP_WAIT,
            // futex
            98 => crate::vdso_ebpf_data::SCHED_CLASS_SYNC_WAIT,
            _ => crate::vdso_ebpf_data::SCHED_CLASS_OTHER,
        };
        class_hist[class] = class_hist[class].saturating_add(*cnt);
    }
    class_hist
}

/// Initialize vDSO getcpu state for the current CPU.
#[cfg(target_arch = "x86_64")]
pub fn init_vdso_getcpu(cpu_id: u32, node_id: u32) {
    use crate::x86_64;
    x86_64::getcpu::init_vdso_getcpu(cpu_id, node_id);
}

#[cfg(target_arch = "loongarch64")]
pub fn init_vdso_getcpu(cpu_id: u32, node_id: u32) {
    use crate::loongarch64;
    loongarch64::getcpu::init_vdso_getcpu(cpu_id, node_id);
}

/// Get the physical address of vDSO data for mapping to userspace
pub fn vdso_data_paddr() -> usize {
    let data_ptr = unsafe { core::ptr::addr_of!(VDSO_DATA.0) as usize };
    virt_to_phys(data_ptr.into()).into()
}

/// Information about loaded vDSO pages for userspace mapping and auxv update.
pub struct VdsoPageInfo {
    pub vdso_paddr_page: axplat::mem::PhysAddr,
    pub vdso_len: usize,
    pub vdso_size: usize,
    pub vdso_page_offset: usize,
    pub alloc_info: Option<(usize, usize)>,
}

/// Load vDSO into the given user address space and update auxv accordingly.
pub fn prepare_vdso_pages(vdso_kstart: usize, vdso_kend: usize) -> AxResult<VdsoPageInfo> {
    let orig_vdso_len = vdso_kend - vdso_kstart;
    let orig_page_off = vdso_kstart & (PAGE_SIZE_4K - 1);
   
        let total_size = orig_vdso_len + orig_page_off;
        let num_pages = total_size.div_ceil(PAGE_SIZE_4K);
        let vdso_size = num_pages * PAGE_SIZE_4K;

        let layout = match Layout::from_size_align(vdso_size, PAGE_SIZE_4K) {
            Ok(l) => l,
            Err(_) => return Err(AxError::InvalidExecutable),
        };
        let alloc_ptr = unsafe { alloc_zeroed(layout) };
        if alloc_ptr.is_null() {
            return Err(AxError::InvalidExecutable);
        }
        // destination start where vdso_start should reside
        let dest = unsafe { alloc_ptr.add(orig_page_off) };
        let src = vdso_kstart as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, dest, orig_vdso_len) };
        let alloc_vaddr = alloc_ptr as usize;
        let vdso_paddr_page = virt_to_phys(alloc_vaddr.into());
        Ok(VdsoPageInfo {
            vdso_paddr_page,
            vdso_len: orig_vdso_len,
            vdso_size,
            vdso_page_offset: orig_page_off,
            alloc_info: Some((alloc_vaddr, num_pages)),
        })
}

/// Calculate ASLR-randomized vDSO user address
pub fn calculate_vdso_aslr_addr(
    vdso_kstart: usize,
    vdso_kend: usize,
    vdso_page_offset: usize,
) -> (usize, usize) {
    use rand_core::RngCore;
    use rand_pcg::Pcg64Mcg;

    const VDSO_USER_ADDR_BASE: usize = 0x7f00_0000;
    const VDSO_ASLR_PAGES: usize = 256;

    let seed: u128 = (monotonic_time_nanos() as u128)
        ^ ((vdso_kstart as u128).rotate_left(13))
        ^ ((vdso_kend as u128).rotate_left(37));
    let mut rng = Pcg64Mcg::new(seed);
    let page_off: usize = (rng.next_u64() as usize) % VDSO_ASLR_PAGES;
    let base_addr = VDSO_USER_ADDR_BASE + page_off * PAGE_SIZE_4K;
    let vdso_addr = if vdso_page_offset != 0 {
        base_addr.wrapping_add(vdso_page_offset)
    } else {
        base_addr
    };

    (base_addr, vdso_addr)
}

/// Load vDSO into the given user address space and update auxv accordingly.
pub fn load_vdso_data<F1, F2, F3>(auxv: &mut Vec<AuxEntry>, f1: F1, f2: F2, f3: F3) -> AxResult<()>
where
    F1: FnOnce(usize, axplat::mem::PhysAddr, usize) -> AxResult<()>,
    F2: FnOnce(usize, usize) -> AxResult<()>,
    F3: FnMut(
        usize,
        axplat::mem::PhysAddr,
        usize,
        &xmas_elf::program::ProgramHeader64,
    ) -> AxResult<()>,
{
    unsafe extern "C" {
        static vdso_start: u8;
        static vdso_end: u8;
    }
    let (vdso_kstart, vdso_kend) = unsafe {
        (
            &vdso_start as *const u8 as usize,
            &vdso_end as *const u8 as usize,
        )
    };
    info!("vdso_kstart: {vdso_kstart:#x}, vdso_kend: {vdso_kend:#x}");

    if vdso_kend <= vdso_kstart {
        warn!(
            "vDSO binary is missing or invalid: vdso_kstart={vdso_kstart:#x}, \
             vdso_kend={vdso_kend:#x}. vDSO will not be loaded and AT_SYSINFO_EHDR will not be \
             set."
        );
        return Err(AxError::InvalidExecutable);
    }

    let vdso_page_info =
        prepare_vdso_pages(vdso_kstart, vdso_kend).map_err(|_| AxError::InvalidExecutable)?;

    let mut alloc_guard = crate::guard::VdsoAllocGuard::new(vdso_page_info.alloc_info);

    let (_base_addr, vdso_user_addr) =
        calculate_vdso_aslr_addr(vdso_kstart, vdso_kend, vdso_page_info.vdso_page_offset);

    let (alloc_vaddr, _alloc_pages) = vdso_page_info
        .alloc_info
        .ok_or(AxError::InvalidExecutable)?;
    let vdso_buf_start = alloc_vaddr + vdso_page_info.vdso_page_offset;
    let vdso_base_user = if vdso_page_info.vdso_page_offset == 0 {
        vdso_user_addr
    } else {
        vdso_user_addr - vdso_page_info.vdso_page_offset
    };
    let vdso_buf = unsafe {
        core::slice::from_raw_parts_mut(vdso_buf_start as *mut u8, vdso_page_info.vdso_len)
    };

    apply_minimal_relocations(vdso_buf, vdso_base_user)?;

    match kernel_elf_parser::ELFHeadersBuilder::new(vdso_buf).and_then(|b| {
        let range = b.ph_range();
        b.build(&vdso_buf[range.start as usize..range.end as usize])
    }) {
        Ok(headers) => {
            map_vdso_segments(
                headers,
                vdso_user_addr,
                vdso_page_info.vdso_paddr_page,
                vdso_page_info.vdso_page_offset,
                f3,
            )?;
            alloc_guard.disarm();
        }
        Err(_) => {
            info!("vDSO ELF parsing failed, using fallback mapping");
            let map_user_start = if vdso_page_info.vdso_page_offset == 0 {
                vdso_user_addr
            } else {
                vdso_user_addr - vdso_page_info.vdso_page_offset
            };
            f1(map_user_start, vdso_page_info.vdso_paddr_page, vdso_page_info.vdso_size)?;
            alloc_guard.disarm();
        }
    }

    map_vvar_and_push_aux(auxv, vdso_user_addr, f2)?;

    Ok(())
}

fn map_vvar_and_push_aux<F>(auxv: &mut Vec<AuxEntry>, vdso_user_addr: usize, f: F) -> AxResult<()>
where
    F: FnOnce(usize, usize) -> AxResult<()>,
{
    use crate::config::VVAR_PAGES;
    let vvar_user_addr = vdso_user_addr - VVAR_PAGES * PAGE_SIZE_4K;
    let vvar_paddr = vdso_data_paddr();

    f(vvar_user_addr, vvar_paddr)?;

    info!(
        "Mapped vvar pages at user {:#x}..{:#x} -> paddr {:#x}",
        vvar_user_addr,
        vvar_user_addr + VVAR_PAGES * PAGE_SIZE_4K,
        vvar_paddr,
    );

    let aux_entry = AuxEntry::new(AuxType::SYSINFO_EHDR, vdso_user_addr);
    auxv.push(aux_entry);

    Ok(())
}

fn map_vdso_segments<F>(
    headers: kernel_elf_parser::ELFHeaders,
    vdso_user_addr: usize,
    vdso_paddr_page: axplat::mem::PhysAddr,
    vdso_page_offset: usize,
    mut f: F,
) -> AxResult<()>
where
    F: FnMut(
        usize,
        axplat::mem::PhysAddr,
        usize,
        &xmas_elf::program::ProgramHeader64,
    ) -> AxResult<()>,
{
    info!("vDSO ELF parsed successfully, mapping segments");
    for ph in headers
        .ph
        .iter()
        .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
    {
        let vaddr = ph.virtual_addr as usize;
        let seg_pad = vaddr.align_offset_4k() + vdso_page_offset;
        let seg_align_size =
            (ph.mem_size as usize + seg_pad + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1);

        let map_base_user = vdso_user_addr & !(PAGE_SIZE_4K - 1);
        let seg_user_start = map_base_user + vaddr.align_down_4k();
        let seg_paddr = vdso_paddr_page + vaddr.align_down_4k();

        f(seg_user_start, seg_paddr, seg_align_size, ph)?;
    }
    Ok(())
}

#[cfg(not(target_arch = "riscv64"))]
fn apply_minimal_relocations(_vdso_buf: &mut [u8], _vdso_base_user: usize) -> AxResult<()> {
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn apply_minimal_relocations(vdso_buf: &mut [u8], vdso_base_user: usize) -> AxResult<()> {
    let elf = xmas_elf::ElfFile::new(vdso_buf).map_err(|_| AxError::InvalidExecutable)?;
    let relocate_pairs = elf_parser::get_relocate_pairs(&elf, Some(vdso_base_user));
    let mut patches: Vec<(usize, usize, [u8; core::mem::size_of::<usize>()])> = Vec::new();

    for pair in relocate_pairs {
        let src: usize = pair.src.into();
        let dst: usize = pair.dst.into();
        let count = pair.count;

        if count == 0 || count > core::mem::size_of::<usize>() {
            continue;
        }

        let rela_vaddr = dst
            .checked_sub(vdso_base_user)
            .ok_or(AxError::InvalidExecutable)?;
        let target_off = vaddr_to_file_offset(&elf, rela_vaddr)?;
        let end = target_off
            .checked_add(count)
            .ok_or(AxError::InvalidExecutable)?;

        if end > vdso_buf.len() {
            return Err(AxError::InvalidExecutable);
        }

        let bytes = src.to_ne_bytes();
        patches.push((target_off, count, bytes));
    }

    for (target_off, count, bytes) in patches {
        let end = target_off
            .checked_add(count)
            .ok_or(AxError::InvalidExecutable)?;
        let out = vdso_buf
            .get_mut(target_off..end)
            .ok_or(AxError::InvalidExecutable)?;
        out.copy_from_slice(&bytes[..count]);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn vaddr_to_file_offset(elf: &xmas_elf::ElfFile<'_>, vaddr: usize) -> AxResult<usize> {
    for ph in elf
        .program_iter()
        .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
    {
        let p_offset = ph.offset() as usize;
        let p_vaddr = ph.virtual_addr() as usize;
        let p_filesz = ph.file_size() as usize;

        if vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz {
            return p_offset
                .checked_add(vaddr - p_vaddr)
                .ok_or(AxError::InvalidExecutable);
        }
    }
    Err(AxError::InvalidExecutable)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn get_trampoline_addr(auxv: &[AuxEntry]) -> Option<usize> {
    let vdso_base = auxv
        .iter()
        .find(|entry| entry.get_type() == AuxType::SYSINFO_EHDR)
        .map(|entry| entry.value());

    if vdso_base.is_none() {
        warn!("get_trampoline_addr: AT_SYSINFO_EHDR not found in auxv");
        return None;
    }
    let vdso_base = vdso_base.unwrap();
    info!("get_trampoline_addr: found vdso_base={:#x}", vdso_base);

    let mut sigreturn_offset: Option<usize> = None;

    unsafe {
        unsafe extern "C" {
            static vdso_start: u8;
            static vdso_end: u8;
        }
        let (start, end) = (
            &vdso_start as *const u8 as usize,
            &vdso_end as *const u8 as usize,
        );
        if end > start {
            sigreturn_offset = Some(crate::config::SIGRETURN_SYM_OFFSET);
        }
    }

    let sigreturn_offset = sigreturn_offset.unwrap_or_default();
    let addr = vdso_base + sigreturn_offset;
    info!(
        "get_trampoline_addr: vdso_base={:#x}, offset={:#x}, result={:#x}",
        vdso_base, sigreturn_offset, addr
    );
    Some(addr)
}

#[cfg(target_arch = "x86_64")]
pub fn get_trampoline_addr(_auxv: &[AuxEntry]) -> Option<usize> {
    None
}
