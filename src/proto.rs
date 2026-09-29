pub mod openshell {
    pub mod extension {
        pub mod v1 {
            tonic::include_proto!("openshell.extension.v1");
        }
    }
    pub mod middleware {
        pub mod v1 {
            tonic::include_proto!("openshell.middleware.v1");
        }
    }
}
