fn main() {
    // Bake in the target triple for self-update asset selection.
    println!(
        "cargo:rustc-env=BUILD_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
