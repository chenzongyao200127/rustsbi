use crate::HartMask;
#[cfg(feature = "machine")]
use riscv::register::{marchid, mimpid, mvendorid};
use spec::binary::{Physical, SbiRet, SharedPtr};

/// RustSBI trait including standard extensions.
pub trait RustSBI {
    /// Handle supervisor environment call with given parameters and return the `SbiRet` result.
    fn handle_ecall(&self, extension: usize, function: usize, param: [usize; 6]) -> SbiRet;
}

/// Machine information for SBI environment.
///
/// This trait is useful to build an SBI environment when RustSBI is not run directly on RISC-V machine mode.
pub trait MachineInfo {
    /// Vendor ID for the supervisor environment.
    ///
    /// Provides JEDEC manufacturer ID of the provider of the core.
    fn mvendorid(&self) -> usize;
    /// Architecture ID for the supervisor environment.
    ///
    /// Encodes the base micro-architecture of the hart.
    fn marchid(&self) -> usize;
    /// Implementation ID for the supervisor environment.
    ///
    /// Provides a unique encoding of the version of the processor implementation.
    fn mimpid(&self) -> usize;
}

/* macro internal structures and functions */

#[doc(hidden)]
pub struct _StandardExtensionProbe {
    pub base: usize,
    pub fence: usize,
    pub timer: usize,
    pub ipi: usize,
    pub hsm: usize,
    pub reset: usize,
    pub pmu: usize,
    pub console: usize,
    pub susp: usize,
    pub cppc: usize,
    pub nacl: usize,
    pub sta: usize,
    // NOTE: don't forget to add to `fn probe_extension` as well
}

#[cfg(feature = "machine")]
#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_base_bare(
    param: [usize; 6],
    function: usize,
    probe: _StandardExtensionProbe,
) -> SbiRet {
    let [param0] = [param[0]];
    let value = match function {
        spec::base::GET_SBI_SPEC_VERSION => (crate::SBI_SPEC_MAJOR << 24) | (crate::SBI_SPEC_MINOR),
        spec::base::GET_SBI_IMPL_ID => crate::IMPL_ID_RUSTSBI,
        spec::base::GET_SBI_IMPL_VERSION => crate::RUSTSBI_VERSION,
        spec::base::PROBE_EXTENSION => {
            // only provides probes to standard extensions. If you have customized extensions to be probed,
            // run it even before this `handle_ecall` function.
            probe_extension(param0, probe)
        }
        spec::base::GET_MVENDORID => mvendorid::read().map(|r| r.bits()).unwrap_or(0),
        spec::base::GET_MARCHID => marchid::read().map(|r| r.bits()).unwrap_or(0),
        spec::base::GET_MIMPID => mimpid::read().map(|r| r.bits()).unwrap_or(0),
        _ => return SbiRet::not_supported(),
    };
    SbiRet::success(value)
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_base_machine_info<T: MachineInfo>(
    param: [usize; 6],
    function: usize,
    machine_info: &T,
    probe: _StandardExtensionProbe,
) -> SbiRet {
    let [param0] = [param[0]];
    let value = match function {
        spec::base::GET_SBI_SPEC_VERSION => (crate::SBI_SPEC_MAJOR << 24) | (crate::SBI_SPEC_MINOR),
        spec::base::GET_SBI_IMPL_ID => crate::IMPL_ID_RUSTSBI,
        spec::base::GET_SBI_IMPL_VERSION => crate::RUSTSBI_VERSION,
        spec::base::PROBE_EXTENSION => {
            // only provides probes to standard extensions. If you have customized extensions to be probed,
            // run it even before this `handle_ecall` function.
            probe_extension(param0, probe)
        }
        spec::base::GET_MVENDORID => machine_info.mvendorid(),
        spec::base::GET_MARCHID => machine_info.marchid(),
        spec::base::GET_MIMPID => machine_info.mimpid(),
        _ => return SbiRet::not_supported(),
    };
    SbiRet::success(value)
}

#[inline(always)]
fn probe_extension(extension: usize, probe: _StandardExtensionProbe) -> usize {
    match extension {
        spec::base::EID_BASE => probe.base,
        spec::time::EID_TIME => probe.timer,
        spec::spi::EID_SPI => probe.ipi,
        spec::rfnc::EID_RFNC => probe.fence,
        spec::srst::EID_SRST => probe.reset,
        spec::hsm::EID_HSM => probe.hsm,
        spec::pmu::EID_PMU => probe.pmu,
        spec::dbcn::EID_DBCN => probe.console,
        spec::susp::EID_SUSP => probe.susp,
        spec::cppc::EID_CPPC => probe.cppc,
        spec::nacl::EID_NACL => probe.nacl,
        spec::sta::EID_STA => probe.sta,
        _ => spec::base::UNAVAILABLE_EXTENSION,
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_fence<T: crate::Fence>(fence: &T, param: [usize; 6], function: usize) -> SbiRet {
    let [param0, param1, param2, param3, param4] =
        [param[0], param[1], param[2], param[3], param[4]];
    let hart_mask = HartMask::from_mask_base(param0, param1);
    match function {
        spec::rfnc::REMOTE_FENCE_I => fence.remote_fence_i(hart_mask),
        spec::rfnc::REMOTE_SFENCE_VMA => fence.remote_sfence_vma(hart_mask, param2, param3),
        spec::rfnc::REMOTE_SFENCE_VMA_ASID => {
            fence.remote_sfence_vma_asid(hart_mask, param2, param3, param4)
        }
        spec::rfnc::REMOTE_HFENCE_GVMA_VMID => {
            fence.remote_hfence_gvma_vmid(hart_mask, param2, param3, param4)
        }
        spec::rfnc::REMOTE_HFENCE_GVMA => fence.remote_hfence_gvma(hart_mask, param2, param3),
        spec::rfnc::REMOTE_HFENCE_VVMA_ASID => {
            fence.remote_hfence_vvma_asid(hart_mask, param2, param3, param4)
        }
        spec::rfnc::REMOTE_HFENCE_VVMA => fence.remote_hfence_vvma(hart_mask, param2, param3),
        _ => SbiRet::not_supported(),
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_timer<T: crate::Timer>(timer: &T, param: [usize; 6], function: usize) -> SbiRet {
    match () {
        #[cfg(target_pointer_width = "64")]
        () => {
            let [param0] = [param[0]];
            match function {
                spec::time::SET_TIMER => {
                    timer.set_timer(param0 as _);
                    SbiRet::success(0)
                }
                _ => SbiRet::not_supported(),
            }
        }
        #[cfg(target_pointer_width = "32")]
        () => {
            let [param0, param1] = [param[0], param[1]];
            match function {
                spec::time::SET_TIMER => {
                    timer.set_timer(concat_u32(param1, param0));
                    SbiRet::success(0)
                }
                _ => SbiRet::not_supported(),
            }
        }
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_ipi<T: crate::Ipi>(ipi: &T, param: [usize; 6], function: usize) -> SbiRet {
    let [param0, param1] = [param[0], param[1]];
    match function {
        spec::spi::SEND_IPI => ipi.send_ipi(HartMask::from_mask_base(param0, param1)),
        _ => SbiRet::not_supported(),
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_hsm<T: crate::Hsm>(hsm: &T, param: [usize; 6], function: usize) -> SbiRet {
    let [param0, param1, param2] = [param[0], param[1], param[2]];
    match function {
        spec::hsm::HART_START => hsm.hart_start(param0, param1, param2),
        spec::hsm::HART_STOP => hsm.hart_stop(),
        spec::hsm::HART_GET_STATUS => hsm.hart_get_status(param0),
        spec::hsm::HART_SUSPEND => {
            if let Ok(suspend_type) = u32::try_from(param0) {
                hsm.hart_suspend(suspend_type, param1, param2)
            } else {
                SbiRet::invalid_param()
            }
        }
        _ => SbiRet::not_supported(),
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_reset<T: crate::Reset>(reset: &T, param: [usize; 6], function: usize) -> SbiRet {
    let [param0, param1] = [param[0], param[1]];
    match function {
        spec::srst::SYSTEM_RESET => match (u32::try_from(param0), u32::try_from(param1)) {
            (Ok(reset_type), Ok(reset_reason)) => reset.system_reset(reset_type, reset_reason),
            (_, _) => SbiRet::invalid_param(),
        },
        _ => SbiRet::not_supported(),
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_pmu<T: crate::Pmu>(pmu: &T, param: [usize; 6], function: usize) -> SbiRet {
    match () {
        #[cfg(target_pointer_width = "64")]
        () => {
            let [param0, param1, param2, param3, param4] =
                [param[0], param[1], param[2], param[3], param[4]];
            match function {
                spec::pmu::NUM_COUNTERS => SbiRet::success(pmu.num_counters()),
                spec::pmu::COUNTER_GET_INFO => pmu.counter_get_info(param0),
                spec::pmu::COUNTER_CONFIG_MATCHING => {
                    pmu.counter_config_matching(param0, param1, param2, param3, param4 as _)
                }
                spec::pmu::COUNTER_START => pmu.counter_start(param0, param1, param2, param3 as _),
                spec::pmu::COUNTER_STOP => pmu.counter_stop(param0, param1, param2),
                spec::pmu::COUNTER_FW_READ => pmu.counter_fw_read(param0),
                spec::pmu::COUNTER_FW_READ_HI => pmu.counter_fw_read_hi(param0),
                _ => SbiRet::not_supported(),
            }
        }
        #[cfg(target_pointer_width = "32")]
        () => {
            let [param0, param1, param2, param3, param4, param5] =
                [param[0], param[1], param[2], param[3], param[4], param[5]];
            match function {
                spec::pmu::NUM_COUNTERS => SbiRet::success(pmu.num_counters()),
                spec::pmu::COUNTER_GET_INFO => pmu.counter_get_info(param0),
                spec::pmu::COUNTER_CONFIG_MATCHING => pmu.counter_config_matching(
                    param0,
                    param1,
                    param2,
                    param3,
                    concat_u32(param5, param4),
                ),
                spec::pmu::COUNTER_START => {
                    pmu.counter_start(param0, param1, param2, concat_u32(param4, param3))
                }
                spec::pmu::COUNTER_STOP => pmu.counter_stop(param0, param1, param2),
                spec::pmu::COUNTER_FW_READ => pmu.counter_fw_read(param0),
                spec::pmu::COUNTER_FW_READ_HI => pmu.counter_fw_read_hi(param0),
                _ => SbiRet::not_supported(),
            }
        }
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_console<T: crate::Console>(
    console: &T,
    param: [usize; 6],
    function: usize,
) -> SbiRet {
    let [param0, param1, param2] = [param[0], param[1], param[2]];
    match function {
        spec::dbcn::CONSOLE_WRITE => {
            let bytes = Physical::new(param0, param1, param2);
            console.write(bytes)
        }
        spec::dbcn::CONSOLE_READ => {
            let bytes = Physical::new(param0, param1, param2);
            console.read(bytes)
        }
        spec::dbcn::CONSOLE_WRITE_BYTE => console.write_byte((param0 & 0xFF) as u8),
        _ => SbiRet::not_supported(),
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_susp<T: crate::Susp>(susp: &T, param: [usize; 6], function: usize) -> SbiRet {
    let [param0, param1, param2] = [param[0], param[1], param[2]];
    match function {
        spec::susp::SUSPEND => match u32::try_from(param0) {
            Ok(sleep_type) => susp.system_suspend(sleep_type, param1, param2),
            _ => SbiRet::invalid_param(),
        },
        _ => SbiRet::not_supported(),
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_cppc<T: crate::Cppc>(cppc: &T, param: [usize; 6], function: usize) -> SbiRet {
    match () {
        #[cfg(target_pointer_width = "64")]
        () => {
            let [param0, param1] = [param[0], param[1]];
            match function {
                spec::cppc::PROBE => match u32::try_from(param0) {
                    Ok(reg_id) => cppc.probe(reg_id),
                    _ => SbiRet::invalid_param(),
                },
                spec::cppc::READ => match u32::try_from(param0) {
                    Ok(reg_id) => cppc.read(reg_id),
                    _ => SbiRet::invalid_param(),
                },
                spec::cppc::READ_HI => match u32::try_from(param0) {
                    Ok(reg_id) => cppc.read_hi(reg_id),
                    _ => SbiRet::invalid_param(),
                },
                spec::cppc::WRITE => match u32::try_from(param0) {
                    Ok(reg_id) => cppc.write(reg_id, param1 as _),
                    _ => SbiRet::invalid_param(),
                },
                _ => SbiRet::not_supported(),
            }
        }
        #[cfg(target_pointer_width = "32")]
        () => {
            let [param0, param1, param2] = [param[0], param[1], param[2]];
            match function {
                spec::cppc::PROBE => cppc.probe(param0 as _),
                spec::cppc::READ => cppc.read(param0 as _),
                spec::cppc::READ_HI => cppc.read_hi(param0 as _),
                spec::cppc::WRITE => cppc.write(param0 as _, concat_u32(param2, param1)),
                _ => SbiRet::not_supported(),
            }
        }
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_nacl<T: crate::Nacl>(nacl: &T, param: [usize; 6], function: usize) -> SbiRet {
    let [param0, param1, param2] = [param[0], param[1], param[2]];
    match function {
        spec::nacl::PROBE_FEATURE => match u32::try_from(param0) {
            Ok(feature_id) => nacl.probe_feature(feature_id),
            _ => SbiRet::invalid_param(),
        },
        spec::nacl::SET_SHMEM => nacl.set_shmem(SharedPtr::new(param0, param1), param2),
        spec::nacl::SYNC_CSR => nacl.sync_csr(param0),
        spec::nacl::SYNC_HFENCE => nacl.sync_hfence(param0),
        spec::nacl::SYNC_SRET => nacl.sync_sret(),
        _ => SbiRet::not_supported(),
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _rustsbi_sta<T: crate::Sta>(sta: &T, param: [usize; 6], function: usize) -> SbiRet {
    let [param0, param1, param2] = [param[0], param[1], param[2]];
    match function {
        spec::sta::SET_SHMEM => sta.set_shmem(SharedPtr::new(param0, param1), param2),
        _ => SbiRet::not_supported(),
    }
}

#[cfg(target_pointer_width = "32")]
#[inline]
const fn concat_u32(h: usize, l: usize) -> u64 {
    ((h as u64) << 32) | (l as u64)
}
