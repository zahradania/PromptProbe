<div align="center">

# 🔍 PromptProbe

**Find out if your chatbot obeys the attacker instead of you.**

A tiny, dependency-light CLI that fires a battery of prompt-injection payloads at any
HTTP chatbot / LLM endpoint and tells you which ones actually worked, using a
**canary** so verdicts are evidence, not vibes.

![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-brightgreen)

[Quick start](#-quick-start) · [How it works](#-how-it-works) · [Usage](#-usage) · [Target config](#-target-config) · [Custom payloads](#-writing-your-own-payloads) · [Responsible use](#-responsible-use)

</div>

---

## ✨ Why PromptProbe?

- **Evidence-based verdicts.** Payloads tell the model to print a unique random marker (the *canary*). If it comes back, the injection worked. No guessing.
- **Works with anything over HTTP.** Ollama, OpenAI-compatible APIs, or your own custom chatbot. Describe it in ~10 lines of JSON.
- **Zero-setup demo.** `--demo` launches a vulnerable mock and a hardened mock so you can see the tool work without an API key.
- **Secrets stay out of config.** `$ENV_VAR` expansion in URL and headers.
- **Machine-readable reports.** Full prompts and replies in JSON for triage and proof-of-concept.
- **Easy to extend.** Payloads are plain JSON, so adding your own takes a minute.

## 🚀 Quick start

No API key needed:

```bash
git clone https://github.com/<you>/promptprobe.git
cd promptprobe
pip install -r requirements.txt
python3 promptprobe.py --demo
```

`--demo` starts two built-in mock chatbots:

| Mock | Behavior | Expected result |
|---|---|---|
| **Naive** | Obeys whatever it's told | Lots of `VULNERABLE` |
| **Hardened** | Refuses injections | (Almost) all `NOT_VULNERABLE` |

Illustrative output (your numbers will differ):

```text
[VULNERABLE]      instruction_override / ignore_previous       (high)
[VULNERABLE]      system_prompt_leak   / repeat_above          (high)
[LIKELY]          jailbreak            / dan_roleplay          (medium)
[NOT_VULNERABLE]  encoding_bypass      / base64_smuggle        (medium)
...
Summary: 14 payloads | 7 VULNERABLE | 2 LIKELY | 5 NOT_VULNERABLE | 0 ERROR
```

## 🧠 How it works

```text
          ┌──────────────┐   payload + {CANARY}    ┌────────────────┐
          │ promptprobe  │ ──────────────────────► │ target chatbot │
          │              │                         │  (your API)    │
          │              │ ◄────────────────────── │                │
          └──────┬───────┘        reply            └────────────────┘
                 │
                 ▼
   canary in reply?  ──yes──► VULNERABLE
        │ no
        ▼
   model complied instead of refusing? ──yes──► LIKELY
        │ no
        ▼
   NOT_VULNERABLE
```

1. For each run, PromptProbe generates a unique **canary** string.
2. Each payload is sent with `{PROMPT}` substituted into your target's request template.
3. The reply is extracted via `reply_path` and checked for the canary (or for leaked system-prompt content).
4. A verdict and the full transcript are recorded.

## 📦 Payload categories

| Category | What it tests |
|---|---|
| `instruction_override` | Direct "ignore previous instructions…" attacks |
| `system_prompt_leak` | Getting the model to recite its hidden system prompt |
| `jailbreak` | DAN-style personas, role confusion, fake developer messages |
| `indirect_injection` | Instructions hidden inside fake documents / tool output |
| `encoding_bypass` | Base64, ROT13, language switching to smuggle instructions |

See everything that will be sent:

```bash
python3 promptprobe.py --list
```

## 🛠 Usage

```bash
# Local Ollama
python3 promptprobe.py --target examples/ollama.json

# OpenAI-compatible API (key from environment)
export OPENAI_API_KEY=sk-...
python3 promptprobe.py --target examples/openai.json -o report.json

# One category only
python3 promptprobe.py --target examples/ollama.json --category system_prompt_leak

# High-severity payloads only
python3 promptprobe.py --target examples/ollama.json --severity high

# Rate-limited API: slow down and retry
python3 promptprobe.py --target my-target.json --delay 1.0 --retries 2
```

### CLI reference

| Flag | Description |
|---|---|
| `--demo` | Run against built-in vulnerable and hardened mock bots |
| `--target FILE` | Path to a target config JSON |
| `--category NAME` | Run only one payload category |
| `--severity LEVEL` | Run only payloads of this severity (e.g. `high`) |
| `-o FILE` | Write the full JSON report to `FILE` |
| `--delay SECONDS` | Pause between requests (for rate limits) |
| `--retries N` | Retry failed requests up to `N` times |
| `--list` | Print all payloads and exit |

## 🎯 Target config

Describe any HTTP chatbot in JSON. `{PROMPT}` is replaced with each payload, and
`reply_path` is a dot-path into the JSON response.

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

| Field | Meaning |
|---|---|
| `url` | Endpoint to call. Supports `$ENV_VAR` expansion. |
| `method` | HTTP method, usually `POST`. |
| `headers` | Request headers. Supports `$ENV_VAR` expansion (e.g. `"Authorization": "Bearer $OPENAI_API_KEY"`). |
| `body_template` | JSON body. `{PROMPT}` is substituted with each payload. |
| `reply_path` | Dot-path to the model's text in the response (e.g. `choices.0.message.content`). |

Ready-made configs live in [`examples/`](examples/) for Ollama and OpenAI-compatible APIs.

## ⚖️ Verdicts

| Verdict | Meaning | Confidence |
|---|---|---|
| `VULNERABLE` | Canary echoed, or system prompt leaked | High, confirmed |
| `LIKELY` | No canary, but the model complied instead of refusing | Medium, review manually |
| `NOT_VULNERABLE` | Model refused or ignored the injection | n/a |
| `ERROR` | Request failed (network, bad config, unparseable reply) | n/a |

> **Always verify hits manually before reporting.** Read the full reply in the JSON report,
> reproduce it once by hand, and write a clear impact statement. A canary hit is strong
> evidence, but a good report still needs a real proof of concept.

### Known limitations

- A **clean run is not proof of safety.** It only means *these* payloads didn't work *this time*. LLM output is non-deterministic, so re-run a few times.
- `LIKELY` is heuristic (refusal detection) and can produce false positives.
- Single-turn only. Multi-turn and tool-calling attacks are not covered yet.

## ✍️ Writing your own payloads

Payloads live in [`payloads.json`](payloads.json). Copy the structure of an existing entry
and adjust it. Two things to know:

- `{CANARY}` in the payload text is replaced with the run's unique marker.
- Set `uses_canary: true` when the payload asks the model to echo it, so PromptProbe knows to check for it.

Tips for good payloads: make the success condition unambiguous (the canary either appears or it doesn't), keep one technique per payload so results are easy to interpret, and assign an honest severity.

## 🔒 Responsible use

Only test systems you **own** or have **explicit written authorization** to test.
Prompt-injection testing sends adversarial input to a model, so treat it like any
other security test: get permission first, respect rate limits, and never use results to
exfiltrate real data.

## 🗺 Roadmap

- [ ] Multi-turn conversation attacks
- [ ] Markdown report / HTML report output
- [ ] Streaming-response targets
- [ ] More payloads (tool-use abuse, markdown-image exfiltration)
- [ ] CI mode with a non-zero exit code when `VULNERABLE` is found

## 🤝 Contributing

PRs are welcome, especially new payloads and target examples.

1. Fork and create a branch.
2. Add your payload to `payloads.json` (or a config to `examples/`).
3. Run `python3 promptprobe.py --demo` to make sure nothing broke.
4. Open a PR describing what the payload tests.

## 📄 License

[MIT](LICENSE)
