.PHONY: run db-up db-down test-flow migrate-up

run:
	go run cmd/auth-server/main.go

db-up:
	docker-compose up -d

db-down:
	docker-compose down

migrate-up:
	@echo "Sleeping to wait for postgres to be ready..." && sleep 3
	docker exec -i auth_postgres psql -U authuser -d authdb < migrations/001_init.sql
	docker exec -i auth_postgres psql -U authuser -d authdb -c "INSERT INTO oauth2_clients (id, secret, domain) VALUES ('demo-client', 'demo-secret', 'http://localhost:8080/callback') ON CONFLICT DO NOTHING;"
