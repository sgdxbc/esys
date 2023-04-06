fn main() {
    prost_build::compile_protos(&["src/messages.proto"], <&[&str]>::default()).unwrap();
}
