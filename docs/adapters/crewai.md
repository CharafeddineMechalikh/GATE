# CrewAI adapter

The CrewAI adapter wraps a `Crew` and guards every tool attached to its agents and tasks. CrewAI dispatches tool calls through `BaseTool._run`, which the adapter shadows in place.

## Example

```python
from crewai import Agent, Crew, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from gate import AgentProfile, gateConfig, wrap_agent


class SearchArgs(BaseModel):
    query: str = Field(description="query text")


class SearchTool(BaseTool):
    name: str = "search"
    description: str = "Search the knowledge base."
    args_schema: type[BaseModel] = SearchArgs

    def _run(self, query: str) -> str:
        return "result"


search = SearchTool()

agent = Agent(
    role="researcher",
    goal="find policies",
    backstory="careful researcher",
    tools=[search],
)
task = Task(
    description="Find the retention policy.",
    expected_output="A policy summary.",
    agent=agent,
)
crew = Crew(agents=[agent], tasks=[task])

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="crew-agent",
        role="researcher",
        allowed_tools={"search"},
    ),
    enabled_checks={"privilege", "dfa"},
)

secure = wrap_agent(crew, "crewai", config)
result = secure.invoke({"topic": "retention"})
secure.terminate()
```

## Discovery

The adapter collects:

- `tool` entries from every `crew.agents[*].tools`, and
- `tool` entries from every `crew.tasks[*].tools`.

Duplicates are removed by object identity. Every collected tool must expose `_run`; otherwise the wrap raises `AdapterError` naming the agent or task that exposed it.

Tools attached only to a task are guarded too:

```python
task.tools = [search]
secure = wrap_agent(crew, "crewai", config)
assert getattr(search, "_gate_enforcement", None) is secure.enforcement
```

## Invocation

| Method | Behavior |
|---|---|
| `invoke(input, **kwargs)` | Calls `crew.kickoff(inputs=...)` under `config.timeout_seconds` |
| `ainvoke(input, **kwargs)` | Uses `kickoff_async` if present; otherwise runs `kickoff` in a thread |
| `get_state()` | Enforcement state |
| `terminate()` | Closes the monitor event loop |

Input handling:

- `kwargs["inputs"]` is copied.
- A dict `input` is merged into it.
- A non-dict `input` is placed under `"input"` unless that key already exists.

The semantic intent anchor is `inputs["input"]` or a string form of the inputs.

## Async tools

`_crewai_native_async(tool)` checks whether the tool's class overrides `BaseTool._arun`. If it does, the async guard awaits it. If not, the async guard runs `_run` in a worker thread. This avoids validating a call twice when CrewAI's default `_arun` simply delegates to `_run`.

## The native dispatch path

CrewAI builds an OpenAI-style function table with `convert_tools_to_openai_schema`. That table calls the tool's `run`/`_run` entry point. The integration test invokes that table directly and asserts that:

- an allowed tool executes and appears in `tool_history`,
- a forbidden tool raises `ToolExecutionBlocked` with `checks_failed == ["privilege"]` and its body never runs,
- a tool attached only to a task is guarded.

This exercises the same dispatch path CrewAI uses, without a model or API key.

## Shared tools

A tool object can belong to only one enforcement. If a tool is shared between two crews or between a crew and an independently wrapped agent, the second wrap raises:

```text
Tool 'search' is already guarded by another GATE enforcement instance
```

Use distinct tool instances per crew, or route both through one wrapped crew.

## Limitations

- Only tools present on `crew.agents[*].tools` and `crew.tasks[*].tools` at wrap time are guarded. Tools CrewAI creates or manages outside those lists, including any injected delegation helpers, are outside the boundary.
- Tools added after wrapping are not guarded.
- Streaming and event-driven kickoff APIs are not wrapped.
- Whether `ToolExecutionBlocked` reaches the caller or is converted into a tool observation depends on CrewAI's executor and its error handling. The guard always runs before the tool body.
- The wrapper does not mediate memory, knowledge sources, or LLM calls.

## Errors and timeouts

A refusal raises from `BaseTool._run`. If CrewAI catches tool errors and feeds them back to the agent, the model may see the refusal text; otherwise the exception propagates out of `kickoff`.

On timeout, the secure wrapper calls `enforcement.abort(...)` and raises the adapter `TimeoutError`. On Windows, `kickoff` may continue in the background because Python cannot kill the worker thread.

## Related pages

- [Adapters overview](README.md)
- [Enforcement plumbing](../enforcement.md)
- [Security model](../security-model.md)
