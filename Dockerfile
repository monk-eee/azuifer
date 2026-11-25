FROM rust:1.99.1-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src/ src/
COPY specs/ specs/
RUN cargo build --locked --release && mkdir /data

FROM scratch AS linux-binary
COPY --from=build /build/target/release/azuifer /azuifer

FROM mcr.microsoft.com/azurelinux/distroless/minimal:3.0@sha256:acf5853dc3651b91bdbf3aee1e5383e689452f6637bd9bf74c9537771cafa6c2
COPY --from=linux-binary /azuifer /azuifer
COPY --from=build --chown=65532:65532 /data /data
COPY LICENSE-MIT LICENSE-APACHE /licenses/
USER 65532:65532
EXPOSE 10000 10005
ENTRYPOINT ["/azuifer"]
CMD ["serve", "--location", "/data"]
