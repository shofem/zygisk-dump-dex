#![allow(non_snake_case)]

use dobby_rs::Address;
use jni::JNIEnv;
use log::{error, info};
use std::arch::naked_asm;
use std::path::Path;
use zygisk_rs::{
    register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs,
};

/* =========================
   CONFIG
   ========================= */

const TARGET_PACKAGE: &str = "com.singleCad.dev.mdt.stj";

const ART_LIBRARIES: &[&str] = &[
    "libdexfile.so",
    "libart.so",
    "libartbase.so",
];

const OPEN_COMMON_SYMBOLS: &[&str] = &[
    // Android 15 (ART mainline)
    "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPNS0_12VerifyResultE",

    // Android 14
    "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE",

    // Android 12–13
    "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE",
];

/* =========================
   GLOBALS
   ========================= */

static mut OLD_OPEN_COMMON: usize = 0;

/* =========================
   MODULE
   ========================= */

struct MyModule {
    api: Api,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("MDT_Zygisk")
                .with_max_level(log::LevelFilter::Info),
        );

        // Validate JNIEnv (DO NOT store)
        let _ = unsafe { JNIEnv::from_raw(env.cast()) }
            .expect("Invalid JNIEnv");

        Self { api }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let result = (|| -> anyhow::Result<()> {
            let env = unsafe {
                JNIEnv::from_raw(self.api.get_jni_env().cast())?
            };

            let pkg = env
                .get_string(unsafe {
                    (args.nice_name as *const jni::objects::JString)
                        .as_ref()
                        .unwrap()
                })?
                .to_string_lossy()
                .into_owned();

            if pkg != TARGET_PACKAGE {
                self.api.set_option(
                    zygisk_rs::ModuleOption::DlcloseModuleLibrary,
                );
                return Ok(());
            }

            info!("[+] Target app detected: {}", pkg);

            let open_common = resolve_open_common()
                .ok_or_else(|| anyhow::anyhow!("OpenCommon not found"))?;

            unsafe {
                OLD_OPEN_COMMON = dobby_rs::hook(
                    open_common as Address,
                    new_open_common_wrapper as Address,
                )? as usize;

                dobby_rs::clear_cache(
                    open_common as _,
                    (open_common + 0x100) as _,
                );
            }

            info!("[+] ART OpenCommon hook installed");
            Ok(())
        })();

        if let Err(e) = result {
            error!("Setup failed: {:?}", e);
        }
    }

    fn post_app_specialize(&mut self, _: &AppSpecializeArgs) {}
    fn pre_server_specialize(&mut self, _: &mut ServerSpecializeArgs) {}
    fn post_server_specialize(&mut self, _: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);

/* =========================
   SYMBOL RESOLUTION
   ========================= */

fn resolve_open_common() -> Option<usize> {
    for lib in ART_LIBRARIES {
        for sym in OPEN_COMMON_SYMBOLS {
            if let Some(addr) = dobby_rs::resolve_symbol(lib, sym) {
                info!(
                    "[+] Resolved {} in {} @ 0x{:x}",
                    sym,
                    lib,
                    addr as usize
                );
                return Some(addr as usize);
            }
        }
    }
    None
}

/* =========================
   TRAMPOLINE
   ========================= */

#[naked]
pub extern "C" fn new_open_common_wrapper() {
    unsafe {
        naked_asm!(
            r#"
            sub sp, sp, 0x80
            stp x29, x30, [sp, #0x00]
            stp x0,  x1,  [sp, #0x10]
            stp x2,  x3,  [sp, #0x20]
            stp x4,  x5,  [sp, #0x30]
            stp x6,  x7,  [sp, #0x40]
            stp x8,  x9,  [sp, #0x50]

            bl {hook}

            ldp x29, x30, [sp, #0x00]
            ldp x0,  x1,  [sp, #0x10]
            ldp x2,  x3,  [sp, #0x20]
            ldp x4,  x5,  [sp, #0x30]
            ldp x6,  x7,  [sp, #0x40]
            ldp x8,  x9,  [sp, #0x50]
            add sp, sp, 0x80

            adrp x16, {old}
            ldr  x16, [x16, #:lo12:{old}]
            br   x16
            "#,
            hook = sym new_open_common,
            old  = sym OLD_OPEN_COMMON,
        );
    }
}

/* =========================
   DEX DUMP LOGIC
   ========================= */

extern "C" fn new_open_common(base: *const u8, size: usize) {
    if base.is_null() || size < 1024 {
        return;
    }

    let dex = unsafe { std::slice::from_raw_parts(base, size) };

    if dex.len() < 4 || &dex[0..4] != b"dex\n" {
        return;
    }

    let dir = "/sdcard/Download/MDT_Dump";
    if let Err(e) = std::fs::create_dir_all(dir) {
        error!("mkdir failed: {:?}", e);
        return;
    }

    let crc = crc::Crc::<u32>::new(&crc::CRC_32_CD_ROM_EDC);
    let checksum = crc.checksum(dex);

    let path = format!("{}/{:08x}.dex", dir, checksum);

    if Path::new(&path).exists() {
        return;
    }

    info!("[+] Dumping DEX ({} bytes) → {}", size, path);

    if let Err(e) = std::fs::write(&path, dex) {
        error!("write failed: {:?}", e);
    }
}
