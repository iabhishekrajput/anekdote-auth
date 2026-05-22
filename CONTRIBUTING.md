# Contributing to Anekdote Auth

Thank you for considering contributing to Anekdote Auth!

## Development Workflow

1. **Fork the repository** — start by forking `iabhishekrajput/anekdote-auth`.
2. **Clone locally** — clone your fork to your local machine.
3. **Environment setup** — you'll need Go 1.26+, Docker, and `make`. Start the background datastores:
   ```bash
   make postgres-up redis-up mailpit-up
   ```
4. **One-time setup** — generate certs and apply migrations:
   ```bash
   cp .env.example .env # copy and fill in local values; loaded automatically
   npm install          # Tailwind CLI
   make generate-certs  # RSA-2048 key pair
   make migrate-up
   ```
5. **Create a branch** — `git checkout -b feature/your-feature-name`.
6. **Make changes** — after editing any `.templ` file, run `make generate`. After editing Tailwind classes, run `make css-build`.
7. **Test and lint** — before pushing:
   ```bash
   make tidy     # go mod tidy + vendor + fmt
   make audit    # vet + staticcheck + tests with -race
   ```
8. **Submit a pull request** — push your branch and open a PR against `main`.

## Adding Features

If you plan on adding a large new feature (a new Grant Type, a new OAuth2 extension, etc.), please open an Issue first to discuss the approach before submitting a large PR.

## Code Style

- Format code with `gofmt` (or `make tidy` which runs it for you).
- Keep dependencies minimal — the core server aims to stay as close to the standard library as practical.
- Use explicit error handling everywhere. Do not silently swallow panics or errors.
