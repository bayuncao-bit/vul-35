# Command Injection Vulnerability in any-agent MCPStdio Configuration

## Summary

A critical Remote Code Execution (RCE) vulnerability exists in the any-agent project's MCPStdio configuration handling. The vulnerability allows arbitrary command execution through insufficient input validation when configuring MCP (Model Context Protocol) servers. When MCPStdio configurations are processed, user-controlled input in the `command` and `args` parameters is directly passed to underlying MCP client implementations without any sanitization or validation, enabling attackers to execute arbitrary system commands with the privileges of the any-agent process.

---

## Description

The any-agent project provides a unified interface for different agent frameworks and supports MCP (Model Context Protocol) integration through the MCPStdio configuration class. The vulnerability stems from the direct use of user-provided `command` and `args` parameters in MCPStdio configurations, which are subsequently passed to various framework-specific MCP client implementations that execute these commands without validation.

The vulnerability manifests across all supported agent frameworks in the any-agent project:

1. **Google ADK Framework** (`src/any_agent/tools/mcp/frameworks/google.py`)
2. **Agno Framework** (`src/any_agent/tools/mcp/frameworks/agno.py`)
3. **Smolagents Framework** (`src/any_agent/tools/mcp/frameworks/smolagents.py`)
4. **TinyAgent Framework** (`src/any_agent/tools/mcp/frameworks/tinyagent.py`)
5. **OpenAI Framework** (`src/any_agent/tools/mcp/frameworks/openai.py`)
6. **LangChain Framework** (`src/any_agent/tools/mcp/frameworks/langchain.py`)

Each framework implementation creates `StdioServerParameters` objects using the unvalidated user input, which are then processed by MCP clients that execute the specified commands.

---

## Affected Code

### Source: MCPStdio Configuration Class

The vulnerability originates in the MCPStdio configuration class defined in `src/any_agent/config.py`:

```python
class MCPStdio(BaseModel):
    command: str
    """The executable to run to start the server.
    
    For example, `docker`, `uvx`, `npx`.
    """
    
    args: Sequence[str]
    """Command line args to pass to the command executable.
    
    For example, `["run", "-i", "--rm", "mcp/fetch"]`.
    """
```

### Sink Points: Framework Implementations

The vulnerability is realized in multiple framework implementations where user-controlled parameters are directly used to construct command execution parameters:

**Google ADK Framework** (`src/any_agent/tools/mcp/frameworks/google.py:59-63`):
```python
server_params = GoogleStdioServerParameters(
    command=self.mcp_tool.command,      # Direct use of user input
    args=list(self.mcp_tool.args),      # Direct use of user input
    env=self.mcp_tool.env,
)
```

**Agno Framework** (`src/any_agent/tools/mcp/frameworks/agno.py:49-53`):
```python
server_params = StdioServerParameters(
    command=self.mcp_tool.command,      # Direct use of user input
    args=list(self.mcp_tool.args),      # Direct use of user input
    env=self.mcp_tool.env,
)
```

Similar patterns exist in all other framework implementations, creating multiple attack vectors for the same underlying vulnerability.

---

## Proof of Concept

A proof-of-concept script (`poc.py`) demonstrates the vulnerability by creating MCPStdio configurations with malicious command parameters:

```python
# Test 1: Command injection via 'command' parameter
vulnerable_mcp_config = MCPStdio(
    command="touch /tmp/command_injection_proof.txt",  # Malicious command
    args=[],
    tools=[]
)

# Test 2: Command injection via 'args' parameter  
vulnerable_mcp_config2 = MCPStdio(
    command="sh",
    args=["-c", "touch /tmp/command_injection_proof2.txt"],  # Malicious args
    tools=[]
)

# Create agent with vulnerable configuration
agent_config = AgentConfig(
    model_id="mistral/mistral-small-latest",
    tools=[vulnerable_mcp_config]
)

# Command execution occurs during agent creation
agent = await AnyAgent.create_async("tinyagent", agent_config)
```

The vulnerability is triggered during the agent creation process when MCP servers are initialized, leading to immediate command execution.

---

## Impact

This vulnerability enables attackers to achieve Remote Code Execution (RCE) in any environment where any-agent processes user-controlled MCPStdio configurations. The impact is particularly severe because:

1. **Immediate Execution**: Commands are executed during agent initialization, not requiring specific user interactions
2. **Cross-Framework**: The vulnerability affects all supported agent frameworks
3. **Privilege Escalation**: Commands execute with the same privileges as the any-agent process
4. **Stealth Attacks**: Malicious commands can be disguised as legitimate MCP server configurations

### Attack Scenarios

**Enterprise AI Deployments**: Attackers could compromise AI systems by providing malicious MCP configurations through APIs or configuration files.

**Cloud Services**: Multi-tenant environments using any-agent could be compromised, allowing attackers to break out of sandboxes and access host systems.

**Development Environments**: Developers using any-agent with untrusted configurations could have their development machines compromised.

---

## Occurrences

The vulnerability exists in multiple locations within the any-agent codebase:

- [Google ADK Framework Implementation](https://github.com/mozilla-ai/any-agent/blob/ee2561098e0cd9c212d8ded2fefa18949ad4db20/src/any_agent/tools/mcp/frameworks/google.py#L59-L63)
- [Agno Framework Implementation](https://github.com/mozilla-ai/any-agent/blob/ee2561098e0cd9c212d8ded2fefa18949ad4db20/src/any_agent/tools/mcp/frameworks/agno.py#L49-L53)
- [Smolagents Framework Implementation](https://github.com/mozilla-ai/any-agent/blob/ee2561098e0cd9c212d8ded2fefa18949ad4db20/src/any_agent/tools/mcp/frameworks/smolagents.py#L42-L46)
- [TinyAgent Framework Implementation](https://github.com/mozilla-ai/any-agent/blob/ee2561098e0cd9c212d8ded2fefa18949ad4db20/src/any_agent/tools/mcp/frameworks/tinyagent.py#L97-L101)
- [OpenAI Framework Implementation](https://github.com/mozilla-ai/any-agent/blob/ee2561098e0cd9c212d8ded2fefa18949ad4db20/src/any_agent/tools/mcp/frameworks/openai.py#L71-L75)
- [LangChain Framework Implementation](https://github.com/mozilla-ai/any-agent/blob/ee2561098e0cd9c212d8ded2fefa18949ad4db20/src/any_agent/tools/mcp/frameworks/langchain.py#L47-L51)
- [MCPStdio Configuration Class](https://github.com/mozilla-ai/any-agent/blob/ee2561098e0cd9c212d8ded2fefa18949ad4db20/src/any_agent/config.py#L37-L67)
