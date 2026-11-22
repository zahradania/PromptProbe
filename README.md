# PromptProbe — LLM Prompt Injection Tester

Test a chatbot / LLM API endpoint for **prompt injection** vulnerabilities.
Send a battery of adversarial payloads, detect which ones the model obeys,
and get a clear report. The core idea is the **canary**: payloads tell the
model to output a unique marker string — if it comes back, the injection
definitively worked.

## Quick start (no API key needed)

```bash
pip install -r requirements.txt
python3 promptprobe.py --demo
```

`--demo` spins up two built-in mock chatbots: one naive (obeys injections)
and one hardened (refuses them). You should see `VULNERABLE` hits against
the vulnerable mock and (almost) all `NOT_VULNERABLE` against the secure one.

## Usage

```bash
# Test Ollama running locally
python3 promptprobe.py --target examples/ollama.json

# Test an OpenAI-compatible API (key from env var)
export OPENAI_API_KEY=sk-...
python3 promptprobe.py --target examples/openai.json -o report.json

# Only run one category
python3 promptprobe.py --target examples/ollama.json --category system_prompt_leak

# Slower, for rate-limited APIs
python3 promptprobe.py --target my-target.json --delay 1.0
```

## Target config

Any HTTP chatbot API, described in JSON. `{PROMPT}` is replaced with each
payload; `reply_path` is a dot-path into the JSON reply.

```json
{
  "url": "http://localhost:11434/api/chat",
  "method": "POST",
  "headers": {"Content-Type": "application/json"},
  "body_template": {
    "model": "llama3",
    "messages": [{"role": "user", "content": "{PROMPT}"}],
    "stream": false
  },
  "reply_path": "message.content"
}
```

Headers and the URL support `$ENV_VAR` expansion (so keys never live in
the config file). See `examples/` for Ollama and OpenAI-compatible configs.

## Payload categories

| Category | What it tests |
|---|---|
| `instruction_override` | "Ignore previous instructions..." direct override |
| `system_prompt_leak` | Getting the model to recite its system prompt |
| `jailbreak` | DAN-style, role confusion, fake developer messages |
| `indirect_injection` | Instructions hidden in fake data / tool output |
| `encoding_bypass` | Base64 / ROT13 / language-switch to smuggle instructions |

Payloads live in `payloads.json` — add your own, `{CANARY}` is replaced
with the canary string. Set `uses_canary: true` when the payload asks the
model to echo it.

## Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | Confirmed: canary echoed, or system prompt leaked |
| `LIKELY` | No canary, but the model complied instead of refusing |
| `NOT_VULNERABLE` | Model refused / ignored the injection |
| `ERROR` | Request failed (network, bad config, bad reply) |

**Always verify a `VULNERABLE` / `LIKELY` hit manually** before reporting:
read the full reply in the JSON report (`-o report.json`), reproduce it
once by hand, and confirm the impact. A canary hit is strong evidence, but
a report still needs a real proof-of-concept and a clear impact statement.

## Scope & safety

Only test systems you own or are authorized to test. Prompt injection
testing sends adversarial input to a model — get permission first, same as
any other security test. Never use results to exfiltrate real data.

## License

MIT
