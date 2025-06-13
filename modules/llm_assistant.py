import json
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
client = Groq(api_key="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")

def generate_insight_from_logs(logs):
    if not logs:
        return "No logs provided for analysis."

    try:
        messages = [log.get("message") or log.get("summary") or json.dumps(log) for log in logs]
        input_text = "\n".join(messages[:50])[:4000]

        prompt = (
            "You are a SOC analyst AI assistant. Analyze the following logs, identify any patterns, "
            "anomalies, or threats, and summarize them in bullet points:\n\n"
            f"{input_text}\n\n"
            "Return clear, human-readable insights:"
        )

        completion = client.chat.completions.create(
            model="meta-llama/llama-4-scout-17b-16e-instruct",
            messages=[{"role": "user", "content": prompt}],
            temperature=1,
            max_completion_tokens=1024,
            top_p=1,
            stream=False,
        )

        return completion.choices[0].message.content.strip()

    except Exception as e:
        return f"❌ Error generating AI insights from Groq: {e}"
