use jni::JNIEnv;
use log::info;
use zygisk_rs::{
    register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs,
};

const TARGET_PACKAGE: &str = "com.singleCad.dev.mdt.stj";

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

        // Validate env (do NOT store)
        let _ = unsafe { JNIEnv::from_raw(env.cast()) }
            .expect("Invalid JNIEnv");

        Self { api }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let Ok(env) = unsafe {
            JNIEnv::from_raw(self.api.get_jni_env().cast())
        } else {
            return;
        };

        let Ok(pkg) = env.get_string(unsafe {
            (args.nice_name as *const jni::objects::JString)
                .as_ref()
                .unwrap()
        }) else {
            return;
        };

        let pkg = pkg.to_string_lossy();

        if pkg != TARGET_PACKAGE {
            // Unload immediately for all other apps
            self.api.set_option(
                zygisk_rs::ModuleOption::DlcloseModuleLibrary,
            );
            return;
        }

        info!("[+] Target app detected: {}", pkg);

        // 👉 Put your OTHER logic here
        // memory patching, libc hooks, etc.
    }

    fn post_app_specialize(&mut self, _: &AppSpecializeArgs) {}
    fn pre_server_specialize(&mut self, _: &mut ServerSpecializeArgs) {}
    fn post_server_specialize(&mut self, _: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);
