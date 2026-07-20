fn main() {
    println!("cargo:rerun-if-changed=assets/icon/app-icon.ico");

    #[cfg(windows)]
    {
        let mut resource = winres::WindowsResource::new();
        resource.set_icon("assets/icon/app-icon.ico");
        resource
            .compile()
            .expect("failed to embed the Windows application icon");
    }
}
