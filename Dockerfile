# AgentSOC — runs the API + dashboard. All demo data is local and fake.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000
# No API key by default -> template mode. Pass -e ANTHROPIC_API_KEY=... to go live.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
