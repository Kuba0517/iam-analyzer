backend:
	cd backend && go build -o bin/server ./cmd/server

run-backend:
	cd backend && air

run-frontend:
	cd frontend && pnpm dev

dev:
	$(MAKE) -j2 run-backend run-frontend

test:
	cd backend && go test ./...

lint:
	cd backend && go vet ./...

clean:
	rm -rf backend/bin