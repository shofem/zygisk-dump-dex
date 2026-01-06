use dobby_rs::Address;
use jni::JNIEnv;
use log::{error, info, trace};
use nix::{fcntl::OFlag, sys::stat::Mode};
use std::arch::naked_asm;
use std::{
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};
use zygisk_rs::{register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs};

// Define the target package directly here for simplicity, or keep reading list.txt
const TARGET_PACKAGE: &str = "com.singleCad.dev.mdt.stj";

struct MyModule {
    api: Api,
    env: JNIEnv<'static>,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("MDT_Zygisk"),
        );
        let env = unsafe { JNIEnv::from_raw(env.cast()).unwrap() };
        Self { api, env }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let mut inner = || -> anyhow::Result<()> {
            // 1. Get Process Name
            let package_name = self
                .env
                .get_string(unsafe {
                    (args.nice_name as *mut jni_sys::jstring as *mut ()
                        as *const jni::objects::JString<'_>)
                        .as_ref()
                        .unwrap()
                })?
                .to_string_lossy()
                .to_string();

            // 2. Filter: Only run on our target app
            // We skip the list.txt complexity to ensure it works 100% for this app
            if package_name != TARGET_PACKAGE {
                self.api.set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
                return Ok(());
            }

            info!("[-] TARGET DETECTED: {}", package_name);
            info!("[-] Preparing to hook OpenCommon...");

            // 3. Resolve the Symbol for Android 12/13/14
            // Note: On Android 14 (Pixel 6), symbol names might vary slightly.
            // This is the standard ART OpenCommon symbol.
            let symbol = "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE";
            
            let open_common = dobby_rs::resolve_symbol("libdexfile.so", symbol)
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve OpenCommon symbol"))?;

            info!("[-] Hooking OpenCommon at 0x{:x}", open_common as usize);

            unsafe {
                OLD_OPEN_COMMON =
                    dobby_rs::hook(open_common, new_open_common_wrapper as Address)? as usize;
            }
            
            info!("[-] Hook SUCCESS. Waiting for DEX load...");

            Ok(())
        };

        if let Err(e) = inner() {
            error!("pre_app_specialize error: {:?}", e);
        }
    }

    fn post_app_specialize(&mut self, _args: &AppSpecializeArgs) {}
    fn pre_server_specialize(&mut self, _args: &mut ServerSpecializeArgs) {}
    fn post_server_specialize(&mut self, _args: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);

static mut OLD_OPEN_COMMON: usize = 0;

// Trampoline to save registers before calling our hook
#[naked]
pub extern "C" fn new_open_common_wrapper() {
    unsafe {
        naked_asm!(
            r#"
            sub sp, sp, 0x280
            stp x29, x30, [sp, #0]
            stp x0, x1, [sp, #0x10]
            stp x2, x3, [sp, #0x20]
            stp x4, x5, [sp, #0x30]
            stp x6, x7, [sp, #0x40]
            stp x8, x9, [sp, #0x50]

            mov x0, x1
            mov x1, x2
            bl {new_open_common}

            ldp x29, x30, [sp, #0]
            ldp x0, x1, [sp, #0x10]
            ldp x2, x3, [sp, #0x20]
            ldp x4, x5, [sp, #0x30]
            ldp x6, x7, [sp, #0x40]
            ldp x8, x9, [sp, #0x50]
            add sp, sp, 0x280
            
            adrp x16, {old_open_common}
            ldr x16, [x16, #:lo12:{old_open_common}]
            br x16
        "#,
        new_open_common = sym new_open_common,
        old_open_common = sym OLD_OPEN_COMMON,
        );
    }
}

// The Hook Logic
extern "C" fn new_open_common(base: usize, size: usize) {
    // Filter small noise (usually system configs)
    if size < 1000 { return; }

    info!("[-] OpenCommon HIT! Base=0x{:x}, Size={}", base, size);

    let dex_data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    
    // Validate Header (dex\n035) to ensure it's actually a DEX
    if dex_data.len() > 4 && &dex_data[0..4] == b"dex\n" {
        let dir = "/sdcard/Download/MDT_Dump";
        
        // Ensure directory exists (might fail if app lacks permissions, 
        // but your logs show it has WRITE_EXTERNAL_STORAGE)
        if let Err(_) = std::fs::create_dir_all(dir) {
            // Fallback to local tmp if sdcard fails
            let _ = std::fs::create_dir_all("/data/local/tmp/MDT_Dump");
        }

        let crc = crc::Crc::<u32>::new(&crc::CRC_32_CD_ROM_EDC);
        let mut digest = crc.digest();
        digest.update(dex_data);
        let checksum = digest.finalize();

        // Save to /sdcard/Download/MDT_Dump/{checksum}.dex
        let file_path = format!("{}/{:08x}.dex", dir, checksum);
        let path = Path::new(&file_path);

        if !path.exists() {
            if let Err(e) = std::fs::write(&file_path, dex_data) {
                error!("Failed to write DEX: {:?}", e);
            } else {
                info!("MATCH! Dumped decrypted DEX to: {}", file_path);
            }
        }
    }
}
