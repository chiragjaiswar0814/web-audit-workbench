.PHONY: install run test

install:
	python3 -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip && pip install -r requirements.txt
	mkdir -p instance

run:
	. .venv/bin/activate && PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8000

test:
	. .venv/bin/activate && PYTHONPATH=. pytest -q
