package graph

type EdgeType int

const (
	Redundant EdgeType = iota
	MergeableAction
	MergeableResource
	DenyAllowOverlap
)

func (e EdgeType) String() string {
	switch e {
	case Redundant:
		return "Redundant"
	case MergeableAction:
		return "MergeableAction"
	case MergeableResource:
		return "MergeableResource"
	case DenyAllowOverlap:
		return "DenyAllowOverlap"
	default:
		return "Unknown"
	}
}

type Node struct {
	Index       int
	Fingerprint string
}

type Edge struct {
	From int
	To   int
	Type EdgeType
	Meta EdgeMeta
}

type EdgeMeta struct {
	OverlappingActions []string
}
