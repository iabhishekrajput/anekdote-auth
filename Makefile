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
	docker exec -i auth_postgres psql -U authuser -d authdb -c "INSERT INTO oauth2_clients (id, secret, domain, public) VALUES ('724ed9d9-63d2-4f85-81c7-00c19926fb10', 'key_rvRkTEdD31RNtMIk3O6esP26oeCUXYs5BHmQ5E84q4AYdgWG', 'http://localhost:8080/callback', FALSE) ON CONFLICT DO NOTHING;"
	docker exec -i auth_postgres psql -U authuser -d authdb -c "INSERT INTO oauth2_clients (id, secret, domain, public) VALUES ('33738764-9d6b-4067-a987-8d87a060b689', '', 'http://localhost:8080/callback', TRUE) ON CONFLICT DO NOTHING;"
