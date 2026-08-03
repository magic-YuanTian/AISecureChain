# AISecureChain — Front End

React + TypeScript UI for querying the vulnerability knowledge base, exploring
the ontology graph, and running extraction on a URL.

## Development

```bash
npm install
npm start        # http://localhost:3000, API calls proxied to the Flask backend
```

The backend must be running on port 5093 (`cd .. && python app.py`).

## Production

```bash
npm run build
```

Flask serves `build/` from its own port, so the UI and API share an origin —
`src/api.ts` therefore uses a relative `/api` base URL. **Restart the Flask
process after building**; it caches the served files at startup.

## Layout

| Path | Contents |
|------|----------|
| `src/pages/` | Query, Explorer (graph browse), Extraction |
| `src/api.ts` | Typed client for the Flask API — the only place URLs are built |
