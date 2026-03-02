# Contributing to Anekdote Auth

First off, thank you for considering contributing to Anekdote Auth! It's people like you that make open source such a great community.

## Development Workflow

1. **Fork the Repository**: Start by forking `iabhishekrajput/anekdote-auth`.
2. **Clone Locally**: Clone your fork to your local machine.
3. **Environment Setup**: Ensure you have Go 1.22+, Docker, and Redis installed. Start the background datastores via `docker-compose up -d`.
4. **Create a Branch**: Create a feature branch (`git checkout -b feature/your-feature-name`).
5. **Commit Changes**: Make your changes. Please use clear, descriptive commit messages.
6. **Testing**: Run the local test suite if applicable, or manually verify using `make run`. Remember to run `make fmt` and `make lint` before pushing.
7. **Submit a Pull Request**: Push your branch to your fork and submit a PR to the `main` branch of this repository.

## Adding Features

If you plan on adding a large new feature to the OAuth2 structure (such as a new Grant Type), please open an Issue first to discuss the architectural approach before submitting a massive PR.

## Code Style

- Format your code using `go fmt`.
- Limit dependencies to only what's absolutely necessary. We aim to keep the core server as native as possible.
- Use explicit error handling everywhere. Do not silently swallow panics.
