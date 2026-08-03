import axios from "axios";

const API = axios.create({ baseURL: "/api" });

export const fetchStats = () => API.get("/stats").then((r) => r.data);
export const fetchVulnDetail = (id: string) =>
  API.get(`/vulnerability/${id}`).then((r) => r.data);

// RDF / SPARQL
export const fetchRdfStats = () => API.get("/rdf/stats").then((r) => r.data);
export const fetchOntologyGraph = () => API.get("/rdf/ontology-graph").then((r) => r.data);
export const sparqlQuery = (sparql: string) =>
  API.post("/rdf/sparql", { sparql }).then((r) => r.data);
export const rdfNlQuery = (question: string) =>
  API.post("/rdf/nl-query", { question }).then((r) => r.data);
export const subgraphForQuestion = (q: string, sparql: string, limit = 120) =>
  API.post("/rdf/subgraph-for-question", { q, sparql, limit }).then((r) => r.data);

// Local instance knowledge graph
export const fetchKgStatus = () => API.get("/kg/status").then((r) => r.data);
export const fetchKgOverview = (limit = 700) =>
  API.get("/kg/overview", { params: { limit } }).then((r) => r.data);
export const searchKgGraph = (q: string, limit = 120) =>
  API.get("/kg/search", { params: { q, limit } }).then((r) => r.data);
export const fetchKgNeighbors = (id: string, limit = 160) =>
  API.post("/kg/neighbors", { id, limit }).then((r) => r.data);

export const fetchClassData = (className: string, params: Record<string, string | number>) =>
  API.get(`/class-data/${className}`, { params }).then((r) => r.data);

// Extraction pipeline
export const extractFromUrl = (url: string, skipDb = false) =>
  API.post("/extract", { url, skip_db: skipDb }).then((r) => r.data);

export const previewUrl = (url: string) =>
  API.post("/extract/preview", { url }).then((r) => r.data);

// ─── Data Sources (unified with Extract) ───────────────────────────────
export const fetchSources = () => API.get("/sources").then((r) => r.data);
export const fetchSourceDetail = (id: string) =>
  API.get(`/sources/${id}`).then((r) => r.data);
export const extractSourceNew = (id: string, maxNew = 30, limit = 20) =>
  API.post(`/sources/${id}/extract-new`, { max_new: maxNew, limit }).then((r) => r.data);
export const fetchRecentRuns = (sourceId?: string, limit = 20) =>
  API.get("/sources/runs", { params: { source_id: sourceId, limit } }).then((r) => r.data);
export const stopRun = (runId: number) =>
  API.post(`/sources/runs/${runId}/stop`).then((r) => r.data);
export const stopAllRuns = (sourceId?: string) =>
  API.post("/sources/runs/stop-all", { source_id: sourceId }).then((r) => r.data);
export const discoverAllSources = (maxNew = 30) =>
  API.post("/sources/discover-all", { max_new: maxNew }).then((r) => r.data);

// ─── Flat URL list (simplified) ───────────────────────────────────────
export const fetchUrls = () => API.get("/urls").then((r) => r.data);
export const addUrl = (url: string) =>
  API.post("/urls", { url }).then((r) => r.data);
export const deleteUrl = (urlId: number) =>
  API.delete(`/urls/${urlId}`).then((r) => r.data);
export const clearAllUrls = () =>
  API.delete("/urls").then((r) => r.data);
export const previewUrlById = (urlId: number) =>
  API.post(`/urls/${urlId}/preview`).then((r) => r.data);
export const mergeUrlById = (urlId: number) =>
  API.post(`/urls/${urlId}/merge`).then((r) => r.data);
export const extractUrlById = (urlId: number) =>
  API.post(`/urls/${urlId}/extract`).then((r) => r.data);
