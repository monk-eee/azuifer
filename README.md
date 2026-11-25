# Azuifer

Azuifer is a proposed, independent Rust implementation of the Azure Storage data plane for local development, CI, and compatibility testing. It targets Blob, Data Lake Storage Gen2 (DFS), Azure Files FileREST, Queue, and Table. The central design choice is that Blob and DFS will operate on the same objects when hierarchical namespace is enabled.

**Status: specification only.** There is no runnable emulator, release artifact, or verified compatibility claim yet. This is not a production storage service or an Azure management-plane emulator.

| Start here | What you'll find |
| --- | --- |
| [Product and technical specification](docs/specs/azuifer.md) | The proposed behavior, compatibility contract, and release criteria |
| [Onboarding](ONBOARDING.md) | How the pieces fit together and where to make a first contribution |
| [Architecture decision records](docs/adr.d/README.md) | Design choices, alternatives, and the evidence each choice will need |
| [Contributing](CONTRIBUTING.md) | How to propose, validate, and review changes |
| [Security policy](SECURITY.md) | How to report a security issue privately |
| [Agent instructions](AGENTS.md) | Constraints for automated contributors |

Azuifer is not affiliated with or endorsed by Microsoft. The repository is licensed under either the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option.
