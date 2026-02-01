package model

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Finding struct {
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Evidence    string   `json:"evidence"`
	StmtIndices []int    `json:"statementIndices"`
}

type ScoreBreakdown struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Score int    `json:"score"`
}

type ScoreResult struct {
	Score     int              `json:"score"`
	Rank      string           `json:"rank"`
	Breakdown []ScoreBreakdown `json:"breakdown"`
}

type Patch struct {
	ID          string                `json:"id"`
	Title       string                `json:"title"`
	Impact      string                `json:"impact"`
	DiffPreview string                `json:"diffPreview"`
	Apply       func(*Policy) *Policy `json:"-"`
}

type GraphNode struct {
	Index  int    `json:"index"`
	Label  string `json:"label"`
	Effect string `json:"effect"`
}

type GraphEdge struct {
	From  int    `json:"from"`
	To    int    `json:"to"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type GraphData struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type AnalyzeResponse struct {
	Original    *Policy     `json:"original"`
	Normalized  *Policy     `json:"normalized"`
	Score       ScoreResult `json:"score"`
	Findings    []Finding   `json:"findings"`
	Suggestions []Patch     `json:"suggestions"`
	Graph       *GraphData  `json:"graph,omitempty"`
}

type ApplyRequest struct {
	Policy   *Policy  `json:"policy"`
	PatchIDs []string `json:"patchIds"`
}

type ApplyResponse struct {
	Simplified *Policy     `json:"simplified"`
	Score      ScoreResult `json:"score"`
	Findings   []Finding   `json:"findings"`
}
