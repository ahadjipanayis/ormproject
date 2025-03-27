import os
import re
import time
from django.conf import settings
from dotenv import load_dotenv
from openai import OpenAI, OpenAIError, RateLimitError, Timeout

env_path = "/home/alexis/projects/ormproject/.env"
load_dotenv(env_path)

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("❌ ERROR: OPENAI_API_KEY is not set. Please check your .env file.")

client = OpenAI(api_key=api_key)

def classify_query(query):
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "Classify the query as 'web_search' or 'no_web_search' based on whether it needs real-time information."},
                {"role": "user", "content": f"Query: {query}\nDoes this require web search? Respond only with 'web_search' or 'no_web_search'."},
            ],
            max_tokens=5
        )
        return response.choices[0].message.content.strip() == "web_search"
    except Exception as e:
        print(f"Error in classify_query: {str(e)}")
        return False

def fetch_web_search_results(query, force_web=False):
    try:
        query_lower = query.strip().lower()
        auto_force_web = query_lower.startswith(("web", "search", "live", "latest"))
        use_web_mode = force_web or auto_force_web or classify_query(query)
        model = "gpt-4o-search-preview" if use_web_mode else "gpt-4o"

        print(f"Query sent to OpenAI: '{query}'")
        print(f"Model selected: {model}")

        # Specify desired reply size in the prompt (e.g., 150 words)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a risk analyst. Provide concise insights on risk-related queries, limited to approximately 200 words. Ensure the response is complete and does not end mid-sentence. Include clickable sources if available."},
                {"role": "user", "content": f"Provide insights on: '{query}'. Include sources if possible."},
            ],
            max_tokens=300  # Buffer for ~150 words (1 word ≈ 1.33 tokens)
        )

        result_text = response.choices[0].message.content.strip()
        print(f"Raw response from OpenAI:\n{result_text}")

        url_pattern = re.compile(r"https?://[^\s\)]+")
        bold_pattern = re.compile(r"\*\*(.*?)\*\*")
        seen_links = set()
        formatted_results = []

        sections = re.split(r'\n\s*\n', result_text)
        for section in sections:
            section = section.strip()
            if not section:
                continue

            interpretation = bold_pattern.sub(r"<strong>\1</strong>", section)
            found_link = url_pattern.search(interpretation)
            if found_link:
                url = found_link.group()
                interpretation = interpretation.replace(url, "").strip()
                if url not in seen_links:
                    seen_links.add(url)
                    formatted_results.append({
                        "interpretation": interpretation,
                        "link": f'<a href="{url}" target="_blank" rel="noopener noreferrer">Source</a>'
                    })
            else:
                formatted_results.append({
                    "interpretation": interpretation,
                    "link": "<a href='#'></a>"
                })

        source_type = "Live Web Search" if use_web_mode else "AI Generated"
        model_used = "gpt-4o-search-preview" if use_web_mode else "gpt-4o"
        formatted_results.insert(0, {
            "source_type": source_type,
            "interpretation": f"[{source_type} - Model: {model_used}]",
            "link": "<a href='#'></a>"
        })

        print("Formatted results:")
        for result in formatted_results:
            print(f"- Interpretation: {result['interpretation']}")
            print(f"  Link: {result['link']}")

        return formatted_results

    except Exception as e:
        error_result = [{"source_type": "Error", "interpretation": f"Error fetching search results: {str(e)}", "link": "<a href='#'></a>"}]
        print(f"Error occurred: {str(e)}")
        print(f"Returning: {error_result}")
        return error_result