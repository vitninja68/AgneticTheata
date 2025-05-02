# agent.py
import asyncio
import os # Import os for path manipulation if needed
from dotenv import load_dotenv
from google.genai import types
from google.adk.agents import Agent # Use Agent consistently
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.tools import google_search, built_in_code_execution, agent_tool
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters # SseServerParams removed as we focus on Stdio

# --- Step 1: Load Environment Variables ---
# Load environment variables from .env file expected in the *parent* directory
# Place this near the top, before using env vars like API keys
print("Loading environment variables from '../.env'...")
if load_dotenv('../.env'):
    print("Environment variables loaded successfully.")
else:
    print("Warning: '../.env' file not found or empty.")
    # You might want to add more robust checks here depending on requirements
    # e.g., check if GOOGLE_API_KEY is set directly in the environment
    if not os.getenv('GOOGLE_API_KEY'):
       print("Error: GOOGLE_API_KEY not found in environment or .env file.")
       # Consider exiting or raising an error if the API key is mandatory

# --- Step 2: Function to get MCP Filesystem Tools ---
async def get_mcp_filesystem_tools_async():
  """Connects to the MCP Filesystem server and fetches its tools."""
  print("Attempting to connect to MCP Filesystem server via stdio...")
  try:
      # TODO: IMPORTANT! Change the path below to the ABSOLUTE path
      #          to your target folder on your system.
      # Example Linux/macOS: "/home/user/my_adk_files"
      # Example Windows: "C:/Users/user/my_adk_files"
      # Ensure this path exists and the user running this script has permissions.
      absolute_folder_path = "/path/to/your/folder" # <--- *** CHANGE THIS ***

      if absolute_folder_path == "/path/to/your/folder":
          print("\n" + "="*30)
          print("🛑 CRITICAL: Please update 'absolute_folder_path' in agent.py")
          print(f"   Current value is: '{absolute_folder_path}'")
          print("   This MUST be an absolute path to an existing folder on your machine.")
          print("="*30 + "\n")
          # Decide if you want to raise an error or just warn
          # raise ValueError("MCP server path not configured. Please edit agent.py.")

      print(f"MCP Server target directory: '{absolute_folder_path}'")

      tools, exit_stack = await MCPToolset.from_server(
          # Use StdioServerParameters for local process communication
          connection_params=StdioServerParameters(
              command='npx', # Command to run the server (Node.js package runner)
              args=[       # Arguments for the command
                    "-y",  # Auto-confirm installation if needed
                    "@modelcontextprotocol/server-filesystem", # The MCP server package
                    absolute_folder_path # The folder the server should manage
              ],
              # Optional: Add environment variables if the server needs them
              # env={'VAR_NAME': 'value'}
          )
          # For remote servers, you would use SseServerParams instead:
          # connection_params=SseServerParams(url="http://remote-server:port/path", headers={...})
      )
      print(f"Fetched {len(tools)} tools from MCP server.")
      return tools, exit_stack
  except Exception as e:
      print(f"Error connecting to or fetching tools from MCP server: {e}")
      print("Please ensure:")
      print("  1. You have Node.js and npx installed and in your PATH.")
      print("  2. The path specified for the MCP server is correct and absolute.")
      print("  3. The '@modelcontextprotocol/server-filesystem' package can be run.")
      raise # Re-raise the exception to stop execution if MCP tools are essential

# --- Step 3: Agent Definitions ---
async def get_combined_agent_async():
    """Creates the RootAgent with sub-agents and MCP filesystem tools."""

    # Fetch MCP tools first, as they are needed for the RootAgent definition
    mcp_tools, mcp_exit_stack = await get_mcp_filesystem_tools_async()

    # Define Sub-Agents
    search_agent = Agent(
        model='gemini-2.0-flash', # Using 1.5 flash - adjust if needed
        name='SearchAgent',
        instruction="You are a specialist agent focused on using Google Search effectively to find information.",
        tools=[google_search],
    )
    coding_agent = Agent(
        model='gemini-2.0-flash', # Using 1.5 flash - adjust if needed
        name='CodeAgent',
        instruction="You are a specialist agent focused on executing Python code snippets safely.",
        tools=[built_in_code_execution],
    )

    # Define Root Agent, combining sub-agents and MCP tools
    all_tools = [
        agent_tool.AgentTool(agent=search_agent),
        agent_tool.AgentTool(agent=coding_agent),
    ]
    # Add the dynamically fetched MCP tools to the list
    all_tools.extend(mcp_tools)
    print(f"RootAgent will have {len(all_tools)} total tools (SubAgents + MCP Tools).")

    root_agent = Agent(
        model="gemini-1.5-flash", # Using 1.5 flash - adjust if needed
        name="RootAgent",
        instruction=(
            "You are the main assistant. You can delegate tasks to specialist agents "
            "for searching (SearchAgent) or executing code (CodeAgent). "
            "You also have direct access to tools for interacting with a specific "
            f"local filesystem folder: '{absolute_folder_path}'. Use these tools when asked " # Inform the LLM about the folder
            "about listing files, reading files, writing files, etc., within that folder. "
            "Be precise about file paths relative to the base folder when using filesystem tools."
            " If the user asks a general question, use search. If they ask to run code, use the code agent."
            " If they ask about files, use the filesystem tools directly."
        ),
        tools=all_tools,
    )

    # Return the root agent and the MCP exit stack for cleanup
    return root_agent, mcp_exit_stack

# --- Step 4: Main Execution Logic ---
async def async_main():
    session_service = InMemorySessionService()
    artifacts_service = InMemoryArtifactService() # Included, though maybe not strictly needed for this example

    session = session_service.create_session(
        state={}, app_name='combined_agent_app', user_id='user_combined'
    )

    # Fetch the combined agent and the necessary cleanup stack
    root_agent, mcp_exit_stack = await get_combined_agent_async()

    runner = Runner(
        app_name='combined_agent_app',
        agent=root_agent,
        artifact_service=artifacts_service,
        session_service=session_service,
    )

    # --- User Interaction Loop ---
    print("\n--- Starting Chat ---")
    print("Enter your query (or type 'quit' to exit):")

    while True:
        try:
            query = input("You: ")
            if query.lower() == 'quit':
                break

            if not query:
                continue

            print(f"\nProcessing query: '{query}'...")
            content = types.Content(role='user', parts=[types.Part(text=query)])

            events_async = runner.run_async(
                session_id=session.id, user_id=session.user_id, new_message=content
            )

            final_response = ""
            async for event in events_async:
                # print(f"DEBUG Event received: {event.type} {event.data}") # Optional detailed logging
                if event.type == 'agent_response':
                   if event.data.message and event.data.message.parts:
                       final_response = event.data.message.parts[0].text
                       print(f"Agent: {final_response}")
                elif event.type == 'tool_code_execution_result':
                     print(f"Tool Result (Code): {event.data.result}")
                elif event.type == 'tool_request':
                     print(f"Tool Request: {event.data.tool_name}({event.data.tool_input})")
                elif event.type == 'tool_response':
                     print(f"Tool Response ({event.data.tool_name}): {event.data.tool_output}")
                elif event.type == 'error':
                     print(f"ERROR Event: {event.data}")


        except Exception as e:
            print(f"An error occurred during the chat loop: {e}")
            # Depending on the error, you might want to break or continue

    # --- Crucial Cleanup ---
    print("\nClosing MCP server connection...")
    # Ensure the MCP server process connection is closed using the exit stack
    # Use try/finally to guarantee cleanup even if errors occur above
    try:
        if mcp_exit_stack:
            await mcp_exit_stack.aclose()
            print("MCP server connection closed successfully.")
        else:
            print("No MCP exit stack found (maybe connection failed earlier?).")
    except Exception as e:
        print(f"An error occurred during MCP cleanup: {e}")

    print("Chat finished. Cleanup complete.")


# --- Step 5: Script Entry Point ---
if __name__ == '__main__':
  try:
    # Before running, remind the user about configuration
    print("="*50)
    print("🚀 Starting Combined ADK Agent Demo 🚀")
    print("Reminder: Ensure you have updated 'absolute_folder_path' in agent.py!")
    print("Reminder: Ensure '../.env' exists and contains your GOOGLE_API_KEY.")
    print("Reminder: Ensure Node.js/npx is installed.")
    print("="*50 + "\n")

    asyncio.run(async_main())
  except ValueError as ve:
      # Catch specific configuration errors if raised
      print(f"Configuration Error: {ve}")
  except Exception as e:
    print(f"\n--- An unexpected error occurred ---")
    import traceback
    traceback.print_exc() # Print detailed traceback
    print(f"Error details: {e}")
    print("Exiting due to error.")