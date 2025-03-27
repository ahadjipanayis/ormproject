import os
import time
import logging
import requests
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
from openai import OpenAI, OpenAIError, RateLimitError, Timeout
from orm.models import Risk
import html

# Load environment variables
env_path = "/home/alexis/projects/ormproject/.env"
load_dotenv(env_path)

# Get API Key
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("❌ ERROR: OPENAI_API_KEY is not set. Please check your .env file.")

# Initialize OpenAI client
client = OpenAI(api_key=api_key)


def call_openai_api(prompt, model):
    """
    Calls the OpenAI API with dynamic model selection and retries upon failure.
    Handles rate limits and timeouts gracefully.
    """
    if not model:
        raise ValueError("A valid model must be provided.")

    max_retries = 5
    retry_delay = 60  # Initial delay in seconds
    max_retry_delay = 300  # Max retry delay (5 minutes)

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You generate risk proposals based on descriptions or user input."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=500  # Ensure response length is controlled
            )
            return [line.strip() for line in response.choices[0].message.content.strip().split("\n") if line.strip()]

        except RateLimitError as e:
            logging.warning(f"OpenAI Rate Limit Exceeded: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)  # Exponential backoff
            else:
                return [f"Error: OpenAI rate limit exceeded. Please try again later."]

        except Timeout as e:
            logging.error(f"OpenAI Timeout Error: {e}")
            return [f"Error: OpenAI request timed out. Please try again later."]

        except OpenAIError as e:
            logging.error(f"OpenAI API Error: {e}")
            return [f"OpenAI API Error: {e}"]

        except Exception as e:
            logging.exception(f"Unexpected Error: {e}")
            return [f"Unexpected Error: {e}"]


def generate_risk_proposals(risk=None, custom_context="", model=None):
    """
    Generate risk proposals based on custom context or a given risk object.
    """
    if not model:
        raise ValueError("A valid model must be provided.")

    prompt = custom_context if custom_context else (
        f"Analyze the following risk information:\n\n"
        f"Risk Title: {risk.title}\n"
        f"Risk Description: {risk.description}\n\n"
        "1. Provide a list of mitigation proposals for this risk.\n"
        "2. Also provide a list of possible related risks and proposed KRIs.\n"
        "3. Provide the response in English first, followed by Greek."
    ) if risk else None

    if not prompt:
        raise ValueError("No valid input provided for risk analysis.")

    return call_openai_api(prompt, model=model)


def generate_risk_analysis(risks, model=None):
    """
    Generate analysis for multiple risks using OpenAI.
    """
    if not model:
        raise ValueError("A valid model must be provided.")
    if not risks:
        raise ValueError("No risks provided for analysis.")

    prompt = "Analyze the following risks:\n"
    for risk in risks:
        prompt += f"- {html.unescape(risk.title)}: {html.unescape(risk.description)}\n"
    prompt += (
        "\n1. Provide an analysis of the listed risks.\n"
        "2. Suggest potential mitigation strategies.\n"
        "3. Highlight common indicators or related opportunities.\n"
        "4. Provide the response in English first, followed by Greek."
    )

    return call_openai_api(prompt, model=model)


# OFAC Sanctions Service
class OFACSanctionsService:
    @staticmethod
    def search_individual(name):
        """
        Search for an individual in the OFAC sanctions list.
        """
        url = "https://sanctionslistservice.ofac.treas.gov/entities"
        try:
            response = requests.get(url, params={"q": name})
            response.raise_for_status()
            root = ET.fromstring(response.content)
            results = []

            for entity in root.findall(".//{*}entity"):
                entity_id = entity.get("id")
                sanctions_lists = [sl.text for sl in entity.findall(".//{*}sanctionsList")]
                programs = [sp.text for sp in entity.findall(".//{*}sanctionsProgram")]
                names = [tn.find("{*}formattedFullName").text for tn in entity.findall(".//{*}translation") if tn.find("{*}formattedFullName") is not None]

                matching_names = [n for n in names if name.lower() in n.lower()]
                if matching_names:
                    results.append({
                        "id": entity_id,
                        "names": matching_names,
                        "sanctions_lists": sanctions_lists,
                        "programs": programs,
                    })
            return results

        except requests.RequestException as e:
            logging.error(f"OFAC API Request Error: {e}")
            return {"error": str(e)}
        except ET.ParseError:
            return {"error": "Invalid XML response format"}


# General Sanctions Service
class SanctionsService:
    @staticmethod
    def search_in_sanctions(xml_data, query):
        """
        Search for names matching the query in provided XML data.
        """
        logging.debug("Searching for query: %s", query)
        results = []
        try:
            root = ET.fromstring(xml_data)
            for entity in root.findall(".//entity"):
                entity_id = entity.get("id", "Unknown")
                entity_type = entity.find(".//entityType")
                if entity_type is not None and entity_type.get("refId") == "600":  # Individual
                    names = entity.find(".//names")
                    if names:
                        for name in names.findall(".//name"):
                            translations = name.find(".//translations")
                            if translations:
                                for translation in translations.findall(".//translation"):
                                    full_name = translation.find(".//formattedFullName")
                                    if full_name is not None and query.lower() in full_name.text.lower():
                                        sanctions_list = entity.find(".//sanctionsList/sanctionsList")
                                        results.append({
                                            "name": full_name.text,
                                            "id": entity_id,
                                            "sanctions_list": sanctions_list.text if sanctions_list else "Unknown",
                                        })
        except ET.ParseError:
            return {"error": "Invalid XML format"}
        except Exception as e:
            logging.error(f"Unexpected Sanctions Search Error: {e}")
            return {"error": str(e)}

        return results