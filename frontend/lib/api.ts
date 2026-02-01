export const API_BASE = "/api";

// --- Types mirroring Go backend models ---

export interface Principal {
  Wildcard: boolean;
  Members: Record<string, string[]>;
}

export interface Condition {
  [operator: string]: { [key: string]: string[] };
}

export interface Statement {
  Sid?: string;
  Effect: string;
  Principal?: Principal;
  NotPrincipal?: Principal;
  Action?: string[];
  NotAction?: string[];
  Resource?: string[];
  NotResource?: string[];
  Condition?: Condition;
}

export interface Policy {
  Version: string;
  Id?: string;
  Statement: Statement[];
}

export interface ScoreBreakdown {
  label: string;
  value: string;
  score: number;
}

export interface ScoreResult {
  score: number;
  rank: string;
  breakdown: ScoreBreakdown[];
}

export interface Finding {
  severity: "low" | "medium" | "high";
  title: string;
  explanation: string;
  evidence: string;
  statementIndices: number[];
}

export interface Patch {
  id: string;
  title: string;
  impact: string;
  diffPreview: string;
}

export interface GraphNode {
  index: number;
  label: string;
  effect: string;
}

export interface GraphEdge {
  from: number;
  to: number;
  type: string;
  label: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AnalyzeResponse {
  original: Policy;
  normalized: Policy;
  score: ScoreResult;
  findings: Finding[];
  suggestions: Patch[];
  graph?: GraphData;
}

export interface ApplyResponse {
  simplified: Policy;
  score: ScoreResult;
  findings: Finding[];
  graph?: GraphData;
}

export async function analyzePolicy(
  policyJson: string
): Promise<AnalyzeResponse> {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: policyJson,
  });
  if (!res.ok) {
    const text = await res.text();
    let message = "Analysis failed";
    try {
      const err = JSON.parse(text);
      message = err.error || message;
    } catch {
      message = text || `Server error: ${res.status}`;
    }
    throw new Error(message);
  }
  return res.json();
}

export async function applyPatches(
  policy: Policy,
  patchIds: string[]
): Promise<ApplyResponse> {
  const res = await fetch(`${API_BASE}/apply`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ policy, patchIds }),
  });
  if (!res.ok) {
    const text = await res.text();
    let message = "Apply failed";
    try {
      const err = JSON.parse(text);
      message = err.error || message;
    } catch {
      message = text || `Server error: ${res.status}`;
    }
    throw new Error(message);
  }
  return res.json();
}
