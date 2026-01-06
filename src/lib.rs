use dobby_rs::Address;
use jni::JNIEnv;
use log::{error, info};
use std::arch::naked_asm;
use std::path::Path;
use zygisk_rs::{
    register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs,
};

const TARGET_PACKAGE: &str = "com.singleCad.dev.mdt.stj";

static mut OLD_OPEN_COMMON: usize = 0;

struct MyModule {
    api: Api,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("MDT_Zygisk"),
        );

        // Only validate env here – do NOT store it
        let _ = unsafe { JNIEnv::from_raw(env.cast()) }.expect("JNIEnv invalid");

        Self { api }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let result = (|| -> anyhow::Result<()> {
            let env = unsafe {
                JNIEnv::from_raw(self.api.get_jni_env().cast())?
            };

            let package_name = env
                .get_string(unsafe {
                    (args.nice_name as *const jni::objects::JString)
                        .as_ref()
                        .unwrap()
                })?
                .to_string_lossy()
                .into_owned();

            if package_name != TARGET_PACKAGE {
                self.api.set_option(
                    zygisk_rs::ModuleOption::DlcloseModuleLibrary,
                );
                return Ok(());
            }

            info!("[+] Target detected: {}", package_name);

            let symbol = "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE";

            let open_common = dobby_rs::resolve_symbol("libdexfile.so", symbol)
                .ok_or_else(|| anyhow::anyhow!("OpenCommon not found"))?;

            info!(
                "[+] Hooking OpenCommon @ 0x{:x}",
                open_common as usize
            );

            unsafe {
                OLD_OPEN_COMMON = dobby_rs::hook(
                    open_common,
                    new_open_common_wrapper as Address,
                )? as usize;

                // Flush instruction cache (important on some devices)
                dobby_rs::clear_cache(
                    open_common as _,
                    (open_common as usize + 0x100) as _,
                );
            }

            info!("[+] DEX dumping enabled");
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

/// Trampoline
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

            // x0 = base, x1 = size
            bl {new_open_common}
