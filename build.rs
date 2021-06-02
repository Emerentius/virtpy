fn main() {
    println!("cargo:rerun-if-changed=pip_shim/pip");
    std::process::Command::new("python3")
        .arg("pip_shim/gen_zip_archive.py")
        .status()
        .unwrap();
}
