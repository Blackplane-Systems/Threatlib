.PHONY: install test server dashboard replay docker-up docker-down policy-lint presets

install:
	pip install -e .

test:
	pytest tests/ -v --tb=short

server:
	threatlib-server --config threatlib.yaml --host 0.0.0.0 --port 8000

dashboard:
	threatlib-dashboard --config threatlib.yaml

replay:
	threatlib-replay --config threatlib.yaml --input examples/replay/demo.jsonl

docker-up:
	docker compose up --build

docker-down:
	docker compose down

policy-lint:
	threatlib-policy lint --config threatlib.yaml

presets:
	threatlib-preset list
