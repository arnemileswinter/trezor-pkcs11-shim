use std::path::Path;

fn main() {
    // Use Path::join throughout so the OS-native separator is used and protoc
    // receives a consistent absolute path.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto_dir = Path::new(&manifest)
        .join("vendor")
        .join("trezor-firmware")
        .join("common")
        .join("protob");

    let crypto = proto_dir.join("messages-crypto.proto");
    let common = proto_dir.join("messages-common.proto");

    prost_build::compile_protos(
        &[crypto.to_str().unwrap(), common.to_str().unwrap()],
        &[proto_dir.to_str().unwrap()],
    )
    .expect("failed to compile Trezor proto files");
}
