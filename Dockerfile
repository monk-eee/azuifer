FROM rust:1.100.0-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
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
EXPOSE 10000-10005
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 CMD ["/azuifer", "status", "--ready"]
ENTRYPOINT ["/azuifer"]
CMD ["serve", "--location", "/data"]
