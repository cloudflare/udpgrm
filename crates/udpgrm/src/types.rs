pub const UDP_GRM_WORKING_GEN: libc::c_int = 200;
pub const UDP_GRM_SOCKET_GEN: libc::c_int = 201;
pub const UDP_GRM_DISSECTOR: libc::c_int = 202;
pub const UDP_GRM_FLOW_ASSURE: libc::c_int = 203;
pub const UDP_GRM_SOCKET_APP: libc::c_int = 204;

#[repr(u32)]
#[non_exhaustive]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub enum UdpGrmDissectorType {
    #[default]
    DissectorFlow = 0,
    DissectorCbpf = 1,
    DissectorBespoke = 3,
    DissectorNoop = 4,
}

#[repr(u32)]
#[non_exhaustive]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum UdpGrmDissectorFlags {
    DissectorFlagVerbose = 0x8000,
}

#[repr(C, packed)]
#[non_exhaustive]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct UdpGrmDissectorOpts {
    pub dissector_type: UdpGrmDissectorType,
    pub flow_entry_timeout_sec: u32,
    pub max_apps: u32,
    pub _res2: u32,
    pub label: [u8; 100],
    pub filter_len: u32,
    pub sock_filter: [SockFilter; 64],
}

static_assertions::assert_eq_size!(UdpGrmDissectorOpts, [u8; 116 + 4 + 512]);

#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

static_assertions::assert_eq_size!(SockFilter, [u8; 8]);

#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct UdpGrmSocketGen {
    pub socket_gen: u32,
    pub socket_idx: u32,
    pub grm_cookie: u16,
    _reserved: u16,
}

static_assertions::assert_eq_size!(UdpGrmSocketGen, [u8; 12]);

impl Default for UdpGrmDissectorOpts {
    fn default() -> Self {
        Self {
            dissector_type: UdpGrmDissectorType::DissectorFlow,
            flow_entry_timeout_sec: 0,
            max_apps: 0,
            _res2: 0,
            label: [0; 100],
            filter_len: 0,
            sock_filter: [Default::default(); 64],
        }
    }
}
