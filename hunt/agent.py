# agent.py
import os
import asyncio
from google.adk.agents import Agent
# from google.adk.models.lite_llm import LiteLlm # Optional for multi-model
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types as genai_types 
import warnings
import logging
from google.adk.tools import google_search

system_instruction = """Purpose and Goals:
- Act as a Senior Cyber Threat Intelligence (CTI) Analyst.
- Analyze provided data to extract and assess potential cyber threats, threat actors, and their tactics, techniques, and procedures (TTPs).
- Identify and recommend specific, actionable tasks to mitigate identified risks.
- Use available resources (e.g., google_search) for additional research when necessary.
- Respond with concise, accurate, and evidence-based findings.

Response Style:
- Maintain a professional, analytical, and objective tone.
- Use clear, precise language without unnecessary jargon, special characters, or filler content.
- Deliver outputs in two sections:
  1. Brief Analytical Report: Summarize key findings (1-2 short paragraphs).
  2. Actionable Tasks: List specific, prioritized recommendations.

Always ground conclusions in evidence from the provided data or reputable open sources.
"""

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.ERROR) 

MODEL_GEMINI_2_0_FLASH = "gemini-2.0-flash"
# MODEL_GPT_4O = "openai/gpt-4o"
# MODEL_CLAUDE_SONNET = "anthropic/claude-3-sonnet-20240229"

DEFAULT_APP_NAME = "default_adk_app"
DEFAULT_USER_ID = "default_user"
DEFAULT_SESSION_ID = "default_session" 

def setup_agent_runner(
    agent_model: str = MODEL_GEMINI_2_0_FLASH,
    agent_name: str = "CTI_Agent_v1",
    agent_description: str = "A helpful AI assistant.",
    agent_instruction: str = system_instruction,
    tools: list = None, # Pass any tools (functions) the agent can use
    app_name: str = DEFAULT_APP_NAME,
    user_id: str = DEFAULT_USER_ID,
    session_id: str = DEFAULT_SESSION_ID 
    ) -> tuple[Runner | None, str, str]:
    """
    Initializes and returns the ADK Agent Runner, user_id, and session_id.

    Args:
        agent_model: The language model to use (e.g., "gemini-2.0-flash").
        agent_name: A name for this agent instance.
        agent_description: A description of the agent's purpose.
        agent_instruction: System instructions for the agent's behavior.
        tools: A list of functions the agent can call.
        app_name: An identifier for the application using the agent.
        user_id: An identifier for the user interacting with the agent.
        session_id: An identifier for the conversation session.

    Returns:
        A tuple containing the configured Runner instance (or None on error),
        the user_id, and the session_id. Returns (None, user_id, session_id)
        if the API key is not set.
    """
    print(f"Setting up agent '{agent_name}' with model '{agent_model}'...")

    try:
        cti_agent = Agent(
            name=agent_name,
            model=agent_model,
            description=agent_description,
            instruction=agent_instruction,
            #tools=tools or [], # Ensure tools is a list
            tools=[google_search]
        )
        print(f"Agent '{cti_agent.name}' created successfully.")

        session_service = InMemorySessionService()

        session = session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id
        )
        print(f"Session ready: App='{app_name}', User='{user_id}', Session='{session_id}'")

        runner = Runner(
            agent=cti_agent,
            app_name=app_name,
            session_service=session_service
        )
        print(f"Runner created for agent '{runner.agent.name}'. Setup complete.")

        return runner, user_id, session_id

    except Exception as e:
        print(f"ERROR during agent setup: {e}")
        return None, user_id, session_id # Indicate failure by returning None for runner

async def call_agent_async(
    query: str,
    runner: Runner,
    user_id: str,
    session_id: str) -> str:
    """
    Sends a query to the specified ADK agent runner and session.

    Args:
        query: The user's text query for the agent.
        runner: The initialized ADK Runner instance.
        user_id: The user ID for the session context.
        session_id: The session ID for the conversation context.

    Returns:
        The agent's final text response as a string.
        Returns an error message string if the runner is invalid or an error occurs.
    """
    if not runner or not isinstance(runner, Runner):
         error_msg = "Error: Invalid or uninitialized Runner provided to call_agent_async."
         print(error_msg)
         return error_msg

    print(f"\n>>> Sending Query to Agent (User: {user_id}, Session: {session_id}): {query[:100]}...") # Log truncated query

    content = genai_types.Content(role='user', parts=[genai_types.Part(text=query)])

    final_response_text = "Agent did not produce a final response." # Default message

    try:
        async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
            if event.is_final_response():
                if event.content and event.content.parts:
                    all_parts_text = []
                    for part in event.content.parts:
                        if hasattr(part, 'text'):
                             all_parts_text.append(part.text)

                    if all_parts_text:
                        final_response_text = "\n".join(all_parts_text) 
                    else:
                        final_response_text = "Agent response contained parts but no text."
                elif event.actions and event.actions.escalate:
                    final_response_text = f"Agent Error/Escalation: {event.error_message or 'No specific message.'}"
                break 

    except Exception as e:
        print(f"ERROR during agent execution via run_async: {e}")        
        final_response_text = f"Error during agent execution: {e}"

    print(f"<<< Agent Response Received (Length: {len(final_response_text)} chars)")
    return final_response_text 
