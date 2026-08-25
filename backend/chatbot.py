"""
backend/chatbot.py
Handles interactions with the enterprise LLM API.
"""

import logging
import requests

from core.constants import LLM_API_URL, USERNAME, PASSWORD

log = logging.getLogger("NetworkAI.Chatbot")


def send_to_llm(user_query: str, get_response_only: bool = False) -> str:
    """Send a prompt to the local LLM API and return the response."""
    payload = {"question": user_query}
    try:
        response = requests.post(
            LLM_API_URL, json=payload, auth=(USERNAME, PASSWORD), timeout=60
        )
        response.raise_for_status()
        try:
            llm_answer = response.json().get("answer", "No response from LLM.")
        except ValueError:
            llm_answer = (response.text or "").strip() or "No response from LLM."
    except requests.RequestException as e:
        log.warning("LLM call failed: %s", e)
        llm_answer = f"LLM Error: {e}"

    if get_response_only:
        return llm_answer
    return f"Assistant: {llm_answer}\n"
