use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=pip_shim/pip");
    let mut command = if cfg!(windows) {
        let mut cmd = Command::new("py");
        cmd.arg("-3");
        cmd
    } else {
        Command::new("python3")
    };
    command.arg("pip_shim/gen_zip_archive.py").status().unwrap();
}
