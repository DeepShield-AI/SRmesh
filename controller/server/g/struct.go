package g

type Topology struct {
	PointNum int	`json:"point_num"`
	Points   map[int]PointInfo	`json:"points"`
	EdgeNum  int	`json:"link_num"`
	Edges    []EdgeInfo	`json:"links"`
}

type PointInfo struct {
	Name    string	`json:"name"`
	IP      string	`json:"ip"`
	IPv6    string	`json:"ipv6"`
}

type EdgeInfo struct {
	Node    []int	`json:"points"`
	IP 		string	`json:"ip"`
	IPv6 	string	`json:"ipv6"`
	Weight  float64	`json:"weight"`
	// Bandwidth float64 `json:"bandwidth"`
}
