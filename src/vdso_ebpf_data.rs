use core::sync::atomic::{AtomicU32, Ordering};

pub const MAX_SYSNO: usize = 1024;
pub const SCHED_CLASS_OTHER: usize = 0;
pub const SCHED_CLASS_IO_WAIT: usize = 1;
pub const SCHED_CLASS_SLEEP_WAIT: usize = 2;
pub const SCHED_CLASS_SYNC_WAIT: usize = 3;
pub const SCHED_CLASS_MAX: usize = 4;
pub const TASK_STATE_UNKNOWN: u8 = 0;
pub const TASK_STATE_RUNNING: u8 = 1;
pub const TASK_STATE_READY: u8 = 2;
pub const TASK_STATE_BLOCKED: u8 = 3;
pub const TASK_STATE_EXITED: u8 = 4;

#[repr(C)]
pub struct VdsoEbpfData {
    pub magic: u32,
    pub abi_version: u16,
    pub reserved: u16,
    pub seq: AtomicU32,
    pub max_sysno: u32,
    pub counts: [u32; 1024],
}

impl Default for VdsoEbpfData {
    fn default() -> Self {
        Self::new()
    }
}

impl VdsoEbpfData {
    pub const fn new() -> Self {
        Self {
            magic: 0x44564353,
            abi_version: 1,
            reserved: 0,
            seq: AtomicU32::new(0),
            max_sysno: MAX_SYSNO as u32,
            counts: [0; MAX_SYSNO],
        }
    }

    pub fn update_counts(&mut self, counts: &[u32; MAX_SYSNO]) {
        self.write_seqcount_begin();
        self.magic = 0x44564353;
        self.abi_version = 1;
        self.reserved = 0;
        self.max_sysno = MAX_SYSNO as u32;
        self.counts.copy_from_slice(counts);
        self.write_seqcount_end();
    }

    pub fn write_seqcount_begin(&self) {
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Release);
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    pub fn write_seqcount_end(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Release);
    }
}

#[repr(C)]
pub struct VdsoSchedHintData {
    pub magic: u32,
    pub abi_version: u16,
    pub reserved: u16,
    pub seq: AtomicU32,
    pub max_sysno: u32,
    pub last_update_ns: u64,
    pub total_syscalls: u64,
    pub pressure_score: u32,
    pub tick_count: u64,
    pub runnable_ticks: u64,
    pub blocked_ticks: u64,
    pub idle_ticks: u64,
    pub last_tid: u64,
    pub last_task_state: u8,
    pub last_cpu_id: u8,
    pub last_is_idle: u8,
    pub _pad: u8,
    pub class_hist: [u32; SCHED_CLASS_MAX],
}

impl Default for VdsoSchedHintData {
    fn default() -> Self {
        Self::new()
    }
}

impl VdsoSchedHintData {
    pub const fn new() -> Self {
        Self {
            magic: 0x5348_4348,
            abi_version: 1,
            reserved: 0,
            seq: AtomicU32::new(0),
            max_sysno: MAX_SYSNO as u32,
            last_update_ns: 0,
            total_syscalls: 0,
            pressure_score: 0,
            tick_count: 0,
            runnable_ticks: 0,
            blocked_ticks: 0,
            idle_ticks: 0,
            last_tid: 0,
            last_task_state: TASK_STATE_UNKNOWN,
            last_cpu_id: 0,
            last_is_idle: 0,
            _pad: 0,
            class_hist: [0; SCHED_CLASS_MAX],
        }
    }

    pub fn update_from_class_hist(&mut self, class_hist: &[u32; SCHED_CLASS_MAX], now_ns: u64) {
        self.write_seqcount_begin();

        self.magic = 0x5348_4348;
        self.abi_version = 1;
        self.reserved = 0;
        self.max_sysno = MAX_SYSNO as u32;
        self.last_update_ns = now_ns;
        self.class_hist.copy_from_slice(class_hist);
        self.total_syscalls = class_hist.iter().map(|v| u64::from(*v)).sum::<u64>();
        self.pressure_score = class_hist[SCHED_CLASS_IO_WAIT]
            .saturating_mul(3)
            .saturating_add(class_hist[SCHED_CLASS_SLEEP_WAIT].saturating_mul(2))
            .saturating_add(class_hist[SCHED_CLASS_SYNC_WAIT].saturating_mul(4));

        self.write_seqcount_end();
    }

    pub fn update_task_runtime(
        &mut self,
        now_ns: u64,
        tid: u64,
        task_state: u8,
        cpu_id: u8,
        is_idle: bool,
    ) {
        self.write_seqcount_begin();

        self.last_update_ns = now_ns;
        self.last_tid = tid;
        self.last_task_state = task_state;
        self.last_cpu_id = cpu_id;
        self.last_is_idle = if is_idle { 1 } else { 0 };
        self.tick_count = self.tick_count.saturating_add(1);

        match task_state {
            TASK_STATE_RUNNING | TASK_STATE_READY => {
                self.runnable_ticks = self.runnable_ticks.saturating_add(1);
            }
            TASK_STATE_BLOCKED => {
                self.blocked_ticks = self.blocked_ticks.saturating_add(1);
            }
            _ => {}
        }
        if is_idle {
            self.idle_ticks = self.idle_ticks.saturating_add(1);
        }

        self.write_seqcount_end();
    }

    pub fn write_seqcount_begin(&self) {
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Release);
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    pub fn write_seqcount_end(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Release);
    }
}

#[repr(C)]
#[repr(align(4096))]
pub struct VdsoData {
    pub ebpf_data: VdsoEbpfData,
    pub sched_hint_data: VdsoSchedHintData,
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
            sched_hint_data: VdsoSchedHintData::new(),
        }
    }
}
