# Installation

## Requirements

- Python 3.9 or newer.
- A platform supported by `sentence-transformers` and PyTorch. The semantic firewall is the only stage that needs them; the deterministic stages do not, but the base install includes them.

## Install from a clone

```bash
git clone https://github.com/CharafeddineMechalikh/GATE.git
cd GATE
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows (Git Bash)
source .venv/Scripts/activate

pip install -e ".[all,dev]"
```

`all` installs the four framework extras. `dev` adds pytest and the linting tools used by the test suite. To install only the frameworks you use, pick one or more extras:

```bash
pip install -e ".[langgraph,dev]"
```

## Extras

| Extra | Installs | Use when |
|---|---|---|
| `langchain` | `langchain`, `langchain-openai` | Wrapping `AgentExecutor` or a compiled LangChain agent graph |
| `langgraph` | `langgraph`, `langchain` | Wrapping a compiled `StateGraph` with a `ToolNode` |
| `openai-agents` | `openai-agents` | Wrapping an OpenAI Agents SDK `Agent` |
| `crewai` | `crewai` | Wrapping a CrewAI `Crew` |
| `all` | All four framework extras | Development and the integration tests |
| `firewall` | `sentence-transformers>=2.2.0` | Compatibility alias; the base install already includes the embedding stack |
| `audit` | Nothing | The encrypted audit logger has no mandatory third-party dependency |
| `gemini` | `google-generativeai`, `langchain` | Legacy compatibility extra |
| `llamaindex` | `llama-index` | Legacy compatibility extra; no LlamaIndex adapter ships in this repository |
| `dev` | `pytest`, `pytest-asyncio`, `pytest-cov`, `black`, `ruff`, `mypy` | Running and checking the project |

The `audit` extra is intentionally empty. The encrypted logger uses the standard library for the local and Vault backends. The AWS KMS backend requires `boto3`, which is not installed by default:

```bash
pip install boto3
```

## Framework versions

The integration suite is verified against a single environment containing:

| Package | Verified version |
|---|---|
| `langchain` | 1.4.7 |
| `langgraph` | 1.2.17 |
| `openai-agents` | 0.6.0 |
| `crewai` | 1.15.30 |
| `sentence-transformers` | 6.1.0 |

Those versions are not pinned by this package. Framework internals change, and the adapters depend on a small number of stable dispatch points (`BaseTool._run`/`_arun`, `FunctionTool.on_invoke_tool`, LangGraph `ToolNode.tools_by_name`). If a newer framework release changes one of those points, the integration tests fail loudly rather than silently downgrading enforcement.

## The embedding model

`DefaultSemanticFirewall` constructs a `sentence-transformers` model named by `gateConfig.embedding_model_name`, which defaults to `all-MiniLM-L6-v2`. The first semantic check downloads the model weights (roughly 90 MB) unless they are already cached.

To avoid a download on first use in an offline deployment, preload the model once in the target environment, or set `embedding_model_name` to a model already present in the local Hugging Face cache. The model is loaded when the firewall is constructed, which happens when a `gateMonitor` is built with the semantic stage enabled.

The deterministic stages (`privilege`, `dfa`, `contracts`) and the D-CBF stage do not need the embedding model. Configure `enabled_checks={"privilege", "dfa", "contracts", "dcbf"}` to run without it.

## Verify the installation

```python
import gate
from gate import gateConfig, AgentProfile

print(gate.__version__)  # 1.0.0

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="smoke-test",
        role="tester",
        allowed_tools={"echo"},
    ),
    enabled_checks={"privilege"},
)
print(config.agent_profile.agent_id)
```

To verify the adapters, run the integration suite:

```bash
pytest tests/test_framework_adapters.py -v
```

These tests build real framework objects and exercise native dispatch. They do not call a model, so they need no API key and no network access once the framework packages are installed.

## Windows notes

The adapters enforce invocation timeouts. On POSIX systems in the main thread, a timeout interrupts the call with `SIGALRM`. On Windows, Python cannot interrupt the running call, so the adapter stops waiting at the deadline, records the timeout, and calls `ToolEnforcement.abort()` to deny any further tool calls from that run. The worker thread itself is not forcibly killed. Do not rely on a timeout to undo a tool body that has already started executing on Windows.

## Upgrading

The 0.3.0 release changed the monitor API to async (`validate_action`, `validate_result`) and introduced the shared enforcement layer. Code written against 0.1.x that called monitor methods synchronously, or that assumed adapters only observed calls, must be updated. See the [changelog](https://github.com/CharafeddineMechalikh/GATE/blob/main/CHANGELOG.md).
