fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        // These wire enums are fixed by NVIDIA's proto and cannot be boxed
        // without changing the generated API shape.
        .type_attribute(".", "#[allow(clippy::large_enum_variant)]")
        .compile_protos(
            &["proto/openshell/v0.1.2/supervisor_middleware.proto"],
            &["proto/openshell/v0.1.2"],
        )?;
    Ok(())
}
