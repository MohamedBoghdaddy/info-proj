# info-proj

## Gemini LLM Integration

This project now supports Gemini API scoring alongside rule-based and ML analysis.

- Add your Gemini API key to `backend/.env` as `gemini_api_key=YOUR_KEY`
- Optional overrides: `GEMINI_API_BASE`, `GEMINI_API_MODEL`, `GEMINI_API_TIMEOUT`
- Install backend dependencies from `backend/requirements.txt`
- Start the backend and the frontend, then the UI will compare Rule, ML, and LLM outputs.
