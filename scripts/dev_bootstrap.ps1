$ErrorActionPreference = "Stop"
python -m pip install -e .
threatlib-policy lint --config threatlib.yaml
threatlib-replay --config threatlib.yaml --input examples/replay/demo.jsonl --output replay-output.json
Write-Host "ThreatLib development environment is ready."
