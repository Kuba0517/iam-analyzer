"use client";

import { useState, useMemo } from "react";
import {
  ReactFlow,
  Node,
  Edge,
  Background,
  Controls,
  useNodesState,
  useEdgesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  analyzePolicy,
  applyPatches,
  AnalyzeResponse,
  Policy,
  Finding,
  Patch,
  ScoreResult,
} from "@/lib/api";

export default function Home() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<AnalyzeResponse | null>(null);
  const [simplified, setSimplified] = useState<Policy | null>(null);
  const [selectedPatches, setSelectedPatches] = useState<Set<string>>(new Set());
  const [applyLoading, setApplyLoading] = useState(false);
  const [view, setView] = useState<"input" | "results">("input");
  const [tab, setTab] = useState<"score" | "findings" | "suggestions" | "diff" | "graph">("score");

  async function handleAnalyze() {
    if (!input.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const res = await analyzePolicy(input.trim());
      setReport(res);
      setView("results");
      setTab("score");
      setSimplified(null);
      setSelectedPatches(new Set());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleApply() {
    if (!report) return;
    setApplyLoading(true);
    try {
      const res = await applyPatches(report.normalized, Array.from(selectedPatches));
      setSimplified(res.simplified);
      setTab("diff");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Apply failed");
    } finally {
      setApplyLoading(false);
    }
  }

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setInput(reader.result as string);
    reader.readAsText(file);
  }

  function reset() {
    setView("input");
    setReport(null);
    setSimplified(null);
    setSelectedPatches(new Set());
    setError(null);
  }

  return (
    <div className="min-h-screen" style={{ background: "#f5f6f7" }}>
      {/* Header */}
      <header style={{ background: "#ffffff", borderBottom: "1px solid #e0e0e0" }}>
        <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
          <button onClick={reset} className="flex items-center gap-3 hover:opacity-80">
            <span style={{ color: "#0076ce", fontSize: "20px", fontWeight: 600 }}>IAM Analyzer</span>
          </button>

          {report && view === "results" && (
            <button onClick={reset} className="btn-text">
              + New Analysis
            </button>
          )}
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        {view === "input" && (
          <div className="animate-slide">
            {/* Hero */}
            <div className="mb-8">
              <h1 style={{ fontSize: "28px", fontWeight: 600, color: "#000", marginBottom: "8px" }}>
                Analyze IAM Policy
              </h1>
              <p style={{ color: "#6e6e6e", fontSize: "15px" }}>
                Evaluate complexity, detect security issues, and simplify your AWS IAM policies.
              </p>
            </div>

            {/* Main content */}
            <div className="card p-6" style={{ background: "#ffffff" }}>
              {error && (
                <div className="mb-6 p-4 flex items-start gap-3" style={{ background: "#fde7e9", border: "1px solid #a80000" }}>
                  <span style={{ color: "#a80000", fontWeight: 600 }}>Error:</span>
                  <span style={{ color: "#a80000" }}>{error}</span>
                </div>
              )}

              <div className="mb-5">
                <label className="label">Policy JSON</label>
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder='{"Version": "2012-10-17", "Statement": [...]}'
                  spellCheck={false}
                  className="input-field"
                  style={{
                    width: "100%",
                    height: "320px",
                    resize: "none",
                    fontFamily: "SF Mono, Consolas, Liberation Mono, Menlo, monospace",
                    fontSize: "13px",
                    lineHeight: "1.5"
                  }}
                />
              </div>

              <div className="flex items-center gap-4">
                <button
                  onClick={handleAnalyze}
                  disabled={loading || !input.trim()}
                  className="btn-primary"
                >
                  {loading ? "Analyzing..." : "Analyze Policy"}
                </button>

                <label className="btn-secondary cursor-pointer">
                  Upload File
                  <input type="file" accept=".json" onChange={handleFile} className="hidden" />
                </label>

                {input && (
                  <button onClick={() => setInput("")} className="btn-text ml-auto">
                    Clear
                  </button>
                )}
              </div>
            </div>

            {/* Features */}
            <div className="grid grid-cols-3 gap-6 mt-8">
              {[
                { title: "Security Audit", desc: "Detect overpermissive wildcards and policy conflicts" },
                { title: "Complexity Score", desc: "Get a clear A-F rating for your policy" },
                { title: "Smart Simplify", desc: "One-click patches to reduce complexity" },
              ].map((f, i) => (
                <div key={i} className="card p-5" style={{ background: "#ffffff" }}>
                  <div style={{ fontWeight: 600, color: "#000", marginBottom: "6px" }}>{f.title}</div>
                  <div style={{ fontSize: "13px", color: "#6e6e6e" }}>{f.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {view === "results" && report && (
          <div className="animate-slide">
            {/* Score card */}
            <div className="card p-8 mb-6" style={{ background: "#ffffff" }}>
              <div className="flex items-center gap-10">
                <ScoreRing score={report.score.score} rank={report.score.rank} />
                <div className="flex-1">
                  <div className="label">Complexity Assessment</div>
                  <div style={{ fontSize: "24px", fontWeight: 600, color: "#000", marginBottom: "16px" }}>
                    {report.score.score < 30 ? "Low" : report.score.score < 50 ? "Moderate" : report.score.score < 70 ? "High" : "Very High"} Complexity
                  </div>
                  <div className="flex gap-12">
                    <div>
                      <div style={{ fontSize: "28px", fontWeight: 600, color: "#000" }}>{report.normalized.Statement.length}</div>
                      <div style={{ fontSize: "12px", color: "#6e6e6e", textTransform: "uppercase", letterSpacing: "0.5px" }}>Statements</div>
                    </div>
                    <div>
                      <div style={{ fontSize: "28px", fontWeight: 600, color: "#000" }}>{report.findings?.length || 0}</div>
                      <div style={{ fontSize: "12px", color: "#6e6e6e", textTransform: "uppercase", letterSpacing: "0.5px" }}>Findings</div>
                    </div>
                    <div>
                      <div style={{ fontSize: "28px", fontWeight: 600, color: "#000" }}>{report.suggestions?.length || 0}</div>
                      <div style={{ fontSize: "12px", color: "#6e6e6e", textTransform: "uppercase", letterSpacing: "0.5px" }}>Suggestions</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div className="tabs mb-6">
              {[
                { id: "score" as const, label: "Breakdown" },
                { id: "findings" as const, label: "Findings", count: report.findings?.length },
                { id: "suggestions" as const, label: "Simplify", count: report.suggestions?.length },
                { id: "diff" as const, label: "Diff" },
                { id: "graph" as const, label: "Graph" },
              ].map((t) => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`tab ${tab === t.id ? "active" : ""}`}
                >
                  {t.label}
                  {t.count !== undefined && t.count > 0 && (
                    <span className="ml-2" style={{ background: "#f5f6f7", padding: "2px 8px", fontSize: "12px" }}>
                      {t.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="animate-fade">
              {tab === "score" && <ScoreBreakdown score={report.score} />}
              {tab === "findings" && <FindingsView findings={report.findings || []} />}
              {tab === "suggestions" && (
                <SuggestionsView
                  suggestions={report.suggestions || []}
                  selected={selectedPatches}
                  onToggle={(id) => {
                    setSelectedPatches((prev) => {
                      const next = new Set(prev);
                      next.has(id) ? next.delete(id) : next.add(id);
                      return next;
                    });
                  }}
                  onApply={handleApply}
                  loading={applyLoading}
                />
              )}
              {tab === "diff" && (
                <DiffView
                  original={report.original}
                  normalized={report.normalized}
                  simplified={simplified}
                />
              )}
              {tab === "graph" && (
                <PolicyGraphView policy={report.normalized} simplifiedPolicy={simplified || undefined} />
              )}
            </div>

            {/* Export */}
            <div className="mt-8 pt-6" style={{ borderTop: "1px solid #e0e0e0" }}>
              <div className="flex items-center gap-4">
                <span className="label" style={{ marginBottom: 0 }}>Export</span>
                <ExportButton data={report.normalized} filename="normalized.json" label="Normalized" />
                {simplified && <ExportButton data={simplified} filename="simplified.json" label="Simplified" />}
                <ExportButton data={report} filename="report.json" label="Full Report" />
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function ScoreRing({ score, rank }: { score: number; rank: string }) {
  const circumference = 2 * Math.PI * 40;
  const offset = circumference - (score / 100) * circumference;

  const getColor = () => {
    if (score <= 30) return "#107c10";
    if (score <= 50) return "#0076ce";
    if (score <= 70) return "#d83b01";
    return "#a80000";
  };

  return (
    <div className="score-ring">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle className="track" cx="50" cy="50" r="40" />
        <circle
          className="progress"
          cx="50"
          cy="50"
          r="40"
          stroke={getColor()}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span style={{ fontSize: "28px", fontWeight: 700, color: getColor() }}>{rank}</span>
        <span style={{ fontSize: "12px", color: "#6e6e6e" }}>{score}/100</span>
      </div>
    </div>
  );
}

function ScoreBreakdown({ score }: { score: ScoreResult }) {
  return (
    <div className="card" style={{ background: "#ffffff", overflow: "hidden" }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Factor</th>
            <th>Value</th>
            <th style={{ textAlign: "right" }}>Points</th>
          </tr>
        </thead>
        <tbody>
          {score.breakdown.map((item, i) => (
            <tr key={i}>
              <td>{item.label}</td>
              <td style={{ fontFamily: "var(--font-mono)", color: "#6e6e6e" }}>{item.value}</td>
              <td style={{ textAlign: "right", fontFamily: "var(--font-mono)", fontWeight: 600, color: item.score > 0 ? "#d83b01" : "#9e9e9e" }}>
                +{item.score}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingsView({ findings }: { findings: Finding[] }) {
  if (!findings.length) {
    return (
      <div className="card p-12 text-center" style={{ background: "#ffffff" }}>
        <div style={{ fontSize: "18px", fontWeight: 600, color: "#107c10", marginBottom: "4px" }}>No Issues Found</div>
        <div style={{ color: "#6e6e6e" }}>Your policy looks clean.</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {findings.map((f, i) => (
        <div key={i} className="card p-5" style={{ background: "#ffffff" }}>
          <div className="flex items-start gap-4">
            <span className={`badge badge-${f.severity}`}>{f.severity}</span>
            <div className="flex-1">
              <div style={{ fontWeight: 600, color: "#000", marginBottom: "6px" }}>{f.title}</div>
              <p style={{ color: "#6e6e6e", marginBottom: "10px" }}>{f.explanation}</p>
              {f.evidence && (
                <code className="code">{f.evidence}</code>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function SuggestionsView({
  suggestions,
  selected,
  onToggle,
  onApply,
  loading,
}: {
  suggestions: Patch[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  onApply: () => void;
  loading: boolean;
}) {
  if (!suggestions.length) {
    return (
      <div className="card p-12 text-center" style={{ background: "#ffffff" }}>
        <div style={{ fontSize: "18px", fontWeight: 600, color: "#0076ce", marginBottom: "4px" }}>Already Optimized</div>
        <div style={{ color: "#6e6e6e" }}>No simplifications available.</div>
      </div>
    );
  }

  return (
    <div>
      <div className="space-y-4 mb-6">
        {suggestions.map((s) => {
          const isSelected = selected.has(s.id);
          return (
            <div
              key={s.id}
              onClick={() => onToggle(s.id)}
              className="card cursor-pointer"
              style={{
                background: "#ffffff",
                borderColor: isSelected ? "#0076ce" : undefined,
              }}
            >
              <div className="p-5 flex items-start gap-4">
                <div className={`checkbox ${isSelected ? "checked" : ""}`}>
                  {isSelected && (
                    <svg className="w-3 h-3 text-white" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth={2}>
                      <path d="M2 6l3 3 5-5" />
                    </svg>
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <span style={{ fontWeight: 600, color: "#000" }}>{s.title}</span>
                    <span style={{ fontSize: "12px", fontWeight: 600, color: "#107c10", background: "#dff6dd", padding: "4px 8px" }}>
                      {s.impact}
                    </span>
                  </div>
                  {s.diffPreview && (
                    <pre className="code-block mt-3" style={{ maxHeight: "120px", overflowY: "auto", color: "#6e6e6e" }}>
                      {s.diffPreview.split("\n").slice(0, 8).join("\n")}
                      {s.diffPreview.split("\n").length > 8 && "\n..."}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <button
        onClick={(e) => { e.stopPropagation(); onApply(); }}
        disabled={!selected.size || loading}
        className="btn-primary"
      >
        {loading ? "Applying..." : `Apply ${selected.size} Selected`}
      </button>
    </div>
  );
}

function computeDiff(a: string[], b: string[]): { type: "equal" | "add" | "remove"; text: string }[] {
  const n = a.length;
  const m = b.length;

  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      if (a[i - 1] === b[j - 1]) {
        lcs[i][j] = lcs[i - 1][j - 1] + 1;
      } else {
        lcs[i][j] = Math.max(lcs[i - 1][j], lcs[i][j - 1]);
      }
    }
  }

  const result: { type: "equal" | "add" | "remove"; text: string }[] = [];
  let i = n, j = m;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      result.push({ type: "equal", text: a[i - 1] });
      i--; j--;
    } else if (j > 0 && (i === 0 || lcs[i][j - 1] >= lcs[i - 1][j])) {
      result.push({ type: "add", text: b[j - 1] });
      j--;
    } else {
      result.push({ type: "remove", text: a[i - 1] });
      i--;
    }
  }

  return result.reverse();
}

function DiffView({
  original,
  normalized,
  simplified,
}: {
  original: Policy;
  normalized: Policy;
  simplified: Policy | null;
}) {
  const [mode, setMode] = useState<"normalized" | "simplified">("normalized");

  // Compare Original → Normalized, or Normalized → Simplified
  const left = mode === "simplified" && simplified
    ? JSON.stringify(normalized, null, 2)
    : JSON.stringify(original, null, 2);
  const right = mode === "simplified" && simplified
    ? JSON.stringify(simplified, null, 2)
    : JSON.stringify(normalized, null, 2);

  const diff = computeDiff(left.split("\n"), right.split("\n"));

  const stats = {
    added: diff.filter(d => d.type === "add").length,
    removed: diff.filter(d => d.type === "remove").length,
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex gap-2">
          <button
            onClick={() => setMode("normalized")}
            className={mode === "normalized" ? "btn-primary" : "btn-secondary"}
            style={{ height: "36px", fontSize: "13px" }}
          >
            Original → Normalized
          </button>
          <button
            onClick={() => setMode("simplified")}
            disabled={!simplified}
            className={mode === "simplified" ? "btn-primary" : "btn-secondary"}
            style={{ height: "36px", fontSize: "13px", opacity: simplified ? 1 : 0.5 }}
          >
            Normalized → Simplified
          </button>
        </div>

        <div className="flex items-center gap-4" style={{ fontSize: "14px" }}>
          <span style={{ color: "#107c10", fontWeight: 500 }}>+{stats.added}</span>
          <span style={{ color: "#a80000", fontWeight: 500 }}>-{stats.removed}</span>
        </div>
      </div>

      <div className="card" style={{ background: "#ffffff", overflow: "hidden" }}>
        <pre style={{ margin: 0, maxHeight: "500px", overflowY: "auto" }}>
          {diff.map((line, i) => {
            const bg = line.type === "add" ? "#dff6dd" : line.type === "remove" ? "#fde7e9" : "transparent";
            const color = line.type === "add" ? "#107c10" : line.type === "remove" ? "#a80000" : "#000";
            const prefix = line.type === "add" ? "+" : line.type === "remove" ? "-" : " ";

            return (
              <div key={i} className="diff-line" style={{ background: bg }}>
                <span style={{ display: "inline-block", width: "20px", color: color, fontWeight: 600 }}>{prefix}</span>
                <span style={{ color }}>{line.text}</span>
              </div>
            );
          })}
        </pre>
      </div>
    </div>
  );
}

// --- Policy Graph Visualization ---

function buildPolicyGraph(policy: Policy): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  const rowH = 40;
  const stmtGap = 50;
  const colRoot = 0;
  const colStmt = 200;
  const colAction = 400;
  const colResource = 700;

  // Pre-compute each statement's vertical band
  const bands: { actions: string[]; resources: string[]; yStart: number; totalRows: number }[] = [];
  let cursorY = 0;
  policy.Statement.forEach((stmt) => {
    const actions = (stmt.Action || stmt.NotAction || []).map(
      (a) => `${stmt.NotAction ? "NOT " : ""}${a}`
    );
    const resources = (stmt.Resource || stmt.NotResource || []).map(
      (r) => `${stmt.NotResource ? "NOT " : ""}${r}`
    );
    const totalRows = Math.max(actions.length, resources.length, 1);
    bands.push({ actions, resources, yStart: cursorY, totalRows });
    cursorY += totalRows * rowH + stmtGap;
  });

  const totalH = cursorY - stmtGap;

  // Root node
  nodes.push({
    id: "policy-root",
    position: { x: colRoot, y: totalH / 2 - 18 },
    data: { label: `Policy ${policy.Version}` },
    style: {
      background: "#323130",
      border: "2px solid #323130",
      borderRadius: "8px",
      padding: "8px 16px",
      fontSize: "12px",
      fontWeight: 700,
      color: "#ffffff",
      textAlign: "center" as const,
    },
  });

  policy.Statement.forEach((stmt, si) => {
    const band = bands[si];
    const stmtId = `stmt-${si}`;
    const isAllow = stmt.Effect === "Allow";
    const bandCenterY = band.yStart + (band.totalRows * rowH) / 2 - 18;

    nodes.push({
      id: stmtId,
      position: { x: colStmt, y: bandCenterY },
      data: { label: `${stmt.Sid || `S${si}`}: ${stmt.Effect}` },
      style: {
        background: isAllow ? "#dff6dd" : "#fde7e9",
        border: `2px solid ${isAllow ? "#107c10" : "#a80000"}`,
        borderRadius: "8px",
        padding: "8px 16px",
        fontSize: "12px",
        fontWeight: 700,
        color: isAllow ? "#107c10" : "#a80000",
        textAlign: "center" as const,
      },
    });

    edges.push({
      id: `e-root-${stmtId}`,
      source: "policy-root",
      target: stmtId,
      type: "straight",
      style: { stroke: "#999", strokeWidth: 1.5 },
    });

    // Actions — own column, centered in this statement's band
    const actionsH = band.actions.length * rowH;
    const actionsStartY = band.yStart + (band.totalRows * rowH - actionsH) / 2;
    band.actions.forEach((action, ai) => {
      const id = `${stmtId}-a${ai}`;
      nodes.push({
        id,
        position: { x: colAction, y: actionsStartY + ai * rowH },
        data: { label: action },
        style: {
          background: "#e8f0fe",
          border: "1px solid #4285f4",
          borderRadius: "6px",
          padding: "4px 10px",
          fontSize: "11px",
          fontFamily: "SF Mono, Consolas, Liberation Mono, Menlo, monospace",
          color: "#1a73e8",
        },
      });
      edges.push({
        id: `e-${id}`,
        source: stmtId,
        target: id,
        type: "straight",
        style: { stroke: "#4285f4", strokeWidth: 1.5 },
      });
    });

    // Resources — own column, centered in this statement's band
    const resourcesH = band.resources.length * rowH;
    const resourcesStartY = band.yStart + (band.totalRows * rowH - resourcesH) / 2;
    band.resources.forEach((resource, ri) => {
      const id = `${stmtId}-r${ri}`;
      nodes.push({
        id,
        position: { x: colResource, y: resourcesStartY + ri * rowH },
        data: { label: resource },
        style: {
          background: "#fef7e0",
          border: "1px solid #f9ab00",
          borderRadius: "6px",
          padding: "4px 10px",
          fontSize: "11px",
          fontFamily: "SF Mono, Consolas, Liberation Mono, Menlo, monospace",
          color: "#e37400",
        },
      });
      edges.push({
        id: `e-${id}`,
        source: stmtId,
        target: id,
        type: "straight",
        style: { stroke: "#f9ab00", strokeWidth: 1.5 },
      });
    });
  });

  return { nodes, edges };
}

function PolicyFlowPane({ policy }: { policy: Policy }) {
  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(() => buildPolicyGraph(policy), [policy]);
  const [nodes, , onNodesChange] = useNodesState(layoutNodes);
  const [edges, , onEdgesChange] = useEdgesState(layoutEdges);

  if (!policy.Statement.length) {
    return (
      <div className="flex items-center justify-center h-full" style={{ color: "#6e6e6e" }}>
        No statements to visualize.
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      fitView
      fitViewOptions={{ padding: 0.3 }}
      proOptions={{ hideAttribution: true }}
    >
      <Background />
      <Controls />
    </ReactFlow>
  );
}

function PolicyGraphView({ policy, simplifiedPolicy }: { policy: Policy; simplifiedPolicy?: Policy }) {
  const [mode, setMode] = useState<"original" | "simplified">("original");
  const activePolicy = mode === "simplified" && simplifiedPolicy ? simplifiedPolicy : policy;
  const hasSimplified = !!simplifiedPolicy;

  return (
    <div className="card" style={{ background: "#ffffff" }}>
      <div className="flex items-center gap-2 mb-4">
        <button
          onClick={() => setMode("original")}
          style={{
            padding: "6px 16px",
            borderRadius: "6px",
            border: "1px solid #e0e0e0",
            background: mode === "original" ? "#0076ce" : "#ffffff",
            color: mode === "original" ? "#ffffff" : "#323130",
            cursor: "pointer",
            fontSize: "13px",
            fontWeight: 600,
          }}
        >
          Original
        </button>
        <button
          onClick={() => hasSimplified && setMode("simplified")}
          style={{
            padding: "6px 16px",
            borderRadius: "6px",
            border: "1px solid #e0e0e0",
            background: mode === "simplified" && hasSimplified ? "#107c10" : "#ffffff",
            color: mode === "simplified" && hasSimplified ? "#ffffff" : hasSimplified ? "#323130" : "#b0b0b0",
            cursor: hasSimplified ? "pointer" : "default",
            fontSize: "13px",
            fontWeight: 600,
            opacity: hasSimplified ? 1 : 0.5,
          }}
        >
          After Simplification
        </button>
        {!hasSimplified && (
          <span style={{ fontSize: "12px", color: "#999" }}>Apply patches in the Simplify tab first</span>
        )}
      </div>
      <div style={{ height: "500px" }}>
        <PolicyFlowPane key={mode} policy={activePolicy} />
      </div>
    </div>
  );
}

function ExportButton({ data, filename, label }: { data: unknown; filename: string; label: string }) {
  function download() {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <button onClick={download} className="btn-secondary" style={{ height: "36px", fontSize: "13px" }}>
      {label}
    </button>
  );
}
