# PromptGuard API

[![PyPI version](https://img.shields.io/pypi/v/promptguard-api?color=blue)](https://pypi.org/project/promptguard-api/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/sinescribe/promptguard-api/blob/main/LICENSE)
[![Live Playground](https://img.shields.io/badge/Live_Playground-Try_in_Browser-orange)](https://sinescribe.github.io/promptguard-api/)
[![Deploy to Render](https://img.shields.io/badge/Deploy_to-Render-46E3B7?logo=render&logoColor=white)](https://render.com/deploy?repo=https://github.com/sinescribe/promptguard-api)

Sub-1ms zero-dependency FastAPI prompt-injection, ChatML delimiter spoofing, and Python AST execution firewall for autonomous AI agents.

## Why PromptGuard?

Secondary LLM guardrails add 400ms to 1,200ms of latency and extra token cost on every turn. PromptGuard inspects untrusted prompts, RAG chunks, and tool calls deterministically in under 1ms using:

1. **Direct Override & Jailbreak Signatures (`INJECTION_PATTERNS`):** Catches instruction overrides (`ignore all previous instructions`, `developer mode`, `bypass system prompt`, `system override`, `base64 decode and execute`).
2. **ChatML & Llama Delimiter Spoofing (`DELIMITER_ANOMALIES`):** Detects raw control tokens (`<|im_start|>`, `<|im_end|>`, `[SYSTEM]`, `[INST]`, `<<SYS>>`, `<system>`).
3. **Strict Python AST Execution Sandbox (`ast.walk`):** Parses candidate code with `ast.parse` and flags dangerous builtins (`eval`, `exec`, `__import__`, `compile`) and shell calls (`os.system`, `os.popen`, `subprocess.Popen`, `subprocess.run`, `subprocess.call`, `subprocess.check_output`).

## Quickstart

```bash
pip install promptguard-api
promptguard-api
```

Open `http://127.0.0.1:8000` for the interactive live scan playground or `http://127.0.0.1:8000/docs` for OpenAPI Swagger docs.

### Docker Usage

```bash
docker build -t promptguard-api .
docker run -p 8000:8000 promptguard-api
```

### Example cURL Request

```bash
curl -X POST http://127.0.0.1:8000/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_GUMROAD_LICENSE_KEY" \
  -d '{"prompt": "__import__(\"os\").system(\"whoami\")", "strict_mode": true}'
```

### Python Library Usage

```python
from promptguard_api import analyze_prompt

result = analyze_prompt("Ignore all previous instructions", strict=True)
assert result["safe"] is False
assert result["threat_level"] == "critical"
```

## Pro License & Production Toolkits

- **PromptGuard Pro API License ($15/mo):** [Subscribe on Gumroad](https://sinescribe5.gumroad.com/l/qzubcy) (validates live Gumroad license keys via `X-API-Key`).
- **AI Agent Production Guardrail Cheat Sheet + Python Starter ($5):** [Get Starter Kit](https://sinescribe5.gumroad.com/l/cpfgbj)
- **Autonomous Security & Bug Bounty Recon Kit ($19):** [Get Recon Kit](https://sinescribe5.gumroad.com/l/jyubxd)
- **Production Multi-Agent Architecture & Protocol Pack ($29):** [Get Architecture Pack](https://sinescribe5.gumroad.com/l/phhyon)

## License

MIT License - sinescribe
