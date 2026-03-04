.PHONY: run db-up db-down test-flow migrate-up generate css-build

run:
	SMTP_INSECURE_SKIP_VERIFY=true go run cmd/auth-server/main.go

generate:
	templ generate ./...

css-build:
	npx @tailwindcss/cli -c tailwind.config.js -i ./web/static/tailwind.css -o ./web/static/app.css --minify

db-up:
	docker-compose up -d

db-down:
	docker-compose down

migrate-up:
	@echo "Sleeping to wait for postgres to be ready..." && sleep 3
	docker exec -i auth_postgres psql -U authuser -d authdb < migrations/001_init.sql
	docker exec -i auth_postgres psql -U authuser -d authdb -c "INSERT INTO oauth2_clients (id, secret, domain) VALUES ('demo-client', 'demo-secret', 'http://localhost:8080/callback') ON CONFLICT DO NOTHING;"
	docker exec -i auth_postgres psql -U authuser -d authdb -c "INSERT INTO oauth2_clients (id, secret, domain) VALUES ('demo-public-client', '', 'http://localhost:8080/callback') ON CONFLICT DO NOTHING;"
