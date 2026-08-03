import React, { useState } from "react";
import { BrowserRouter, Routes, Route, NavLink, useLocation } from "react-router-dom";
import Explorer, { INITIAL_EXPLORER_STATE, ExplorerState } from "./pages/Explorer";
import QueryPage, { INITIAL_QUERY_STATE, QueryState } from "./pages/QueryPage";
import ExtractPage from "./pages/ExtractPage";
import VulnDetail from "./pages/VulnDetail";
import "./App.css";

function AppContent() {
  const location = useLocation();
  const [queryState, setQueryState] = useState<QueryState>(INITIAL_QUERY_STATE);
  const [explorerState, setExplorerState] = useState<ExplorerState>(INITIAL_EXPLORER_STATE);

  const explorerNavActive =
    location.pathname === "/" || location.pathname.startsWith("/explorer");

  return (
    <div className="app app--topnav">
      <nav className="topbar">
        <div className="topbar-tabs">
          <NavLink to="/" className={explorerNavActive ? "topbar-link active" : "topbar-link"} end>
            Explorer
          </NavLink>
          <NavLink to="/query" className={({ isActive }) => isActive ? "topbar-link active" : "topbar-link"}>
            Query
          </NavLink>
          <NavLink to="/extract" className={({ isActive }) => isActive ? "topbar-link active" : "topbar-link"}>
            Extract
          </NavLink>
        </div>
      </nav>
      <main className="content content--topnav">
        {/* Explorer stays mounted across tab switches so the force-graph keeps
            its camera/zoom and layout. We only hide it (without changing its
            box size — see .explorer-keepalive.hidden) so ForceGraph2D never
            resets its zoom transform on a dimension change, which was the cause
            of the graph appearing zoomed-in when returning to this tab. */}
        <div className={`explorer-keepalive${explorerNavActive ? "" : " hidden"}`} aria-hidden={!explorerNavActive}>
          <Explorer explorerState={explorerState} setExplorerState={setExplorerState} />
        </div>
        <Routes>
          <Route path="/" element={null} />
          <Route path="/query" element={<QueryPage state={queryState} setState={setQueryState} />} />
          <Route path="/extract" element={<ExtractPage />} />
          <Route path="/vuln/:id" element={<VulnDetail />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
