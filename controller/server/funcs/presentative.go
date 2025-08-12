package funcs

import (
	// "fmt"

	"controller/g"
	"fmt"
)

// // 结构体定义
// type Topology struct {
// 	PointNum int                `json:"point_num"`
// 	Points   map[int]PointInfo  `json:"points"`
// 	EdgeNum  int                `json:"link_num"`
// 	Edges    []EdgeInfo         `json:"links"`
// }

// type PointInfo struct {
// 	Name string `json:"name"`
// 	IP   string `json:"ip"`
// 	IPv6 string `json:"ipv6"`
// }

// type EdgeInfo struct {
// 	Node   []int   `json:"points"`
// 	IP     string  `json:"ip"`
// 	IPv6   string  `json:"ipv6"`
// 	Weight float64 `json:"weight"`
// }

// 获取跨分区探测对
func GetCrossPartitionLinks(slice int, communities map[int]int) {
	if slice >= len(g.Topo) {
		fmt.Println("[GetCrossPartitionLinks]: Invalid slice index")
		return
	}
	topo := g.Topo[slice]

	for _, edge := range topo.Edges {
		nodes := edge.Node
		for i := 0; i < len(nodes); i++ {
			for j := i + 1; j < len(nodes); j++ {
				node1 := nodes[i]
				node2 := nodes[j]
				if communities[node1] != communities[node2] {
					InitTasks[slice][node1] = append(InitTasks[slice][node1], node2)
					InitTasks[slice][node2] = append(InitTasks[slice][node2], node1)
					// if len(InitTasks[slice][node1]) <= len(InitTasks[slice][node2]) {
					// 	InitTasks[slice][node1] = append(InitTasks[slice][node1], node2)
					// } else {
					// 	InitTasks[slice][node2] = append(InitTasks[slice][node2], node1)
					// }
				}
			}
		}
	}
}

// 建立包含关系
func Subset_check(slice int) {
	Dijistra_path(slice)

	type Pair struct {
		source int
		target int
	}
	Paths := make(map[Pair][]int)
	Distances := make(map[Pair]float64)
	topo := g.Topo[slice]

	// fullmesh
	fmt.Printf("Fullmesh for slice %d:\n", slice)
	for node := range topo.Points {
		for node2 := range topo.Points {
			if node != node2 {
				path, _, _ := ShortestPaths.Between(int64(node), int64(node2))
				fmt.Printf("Node %d (%s) --> Node %d (%s) with path: ", node, topo.Points[node].IP, node2, topo.Points[node2].IP)
				for i := 0; i < len(path); i++ {
					fmt.Printf("%d ", path[i].ID())
				}
			}
		}
	}
	fmt.Printf("\n")

	for node := range topo.Points {
		for _, target := range InitTasks[slice][node] {
			path, distance, _ := ShortestPaths.Between(int64(node), int64(target))
			Distances[Pair{node, target}] = distance
			for i := 0; i < len(path); i++ {
				Paths[Pair{node, target}] = append(Paths[Pair{node, target}], int(path[i].ID()))
			}
		}
	}
	father := make(map[Pair]Pair)
	for index, _ := range Paths {
		father[index] = index
	}

	for pair, path := range Paths {
		for pair2, path2 := range Paths {
			// 检查包含关系
			if Distances[pair] < Distances[pair2] {
				for i := 0; i <= len(path2)-len(path); i++ {
					match := true
					for j := 0; j < len(path); j++ {
						if path[j] != path2[i+j] {
							match = false
							break
						}
					}
					if match {
						// path is contained in path2
						father[pair] = father[pair2]
					}
				}
			}
		}
	}
	// 令father[pair] = 包含pair的最长路径
	for _, dad := range father {
		for dad != father[dad] {
			dad = father[dad]
		}
	}

	// 初始化Tasks
	for i := 0; i < len(topo.Points); i++ {
		Tasks[slice][i] = make([]int, 0)
	}

	for pair, dad := range father {
		if pair == dad {
			Tasks[slice][pair.source] = append(Tasks[slice][pair.source], pair.target)
			// print the path
			fmt.Printf("Node %d (%s) --> Node %d (%s) with path: ", pair.source, topo.Points[pair.source].IP, pair.target, topo.Points[pair.target].IP)
			for _, node := range Paths[pair] {
				fmt.Printf("%d ", node)
			}
		}
	}
	fmt.Printf("\n")
	// 输出渐进式检查后的任务分配
	// for node, targets := range Tasks[slice] {
	// 	fmt.Printf("Node %d (%s)--> Node ", node, topo.Points[node].IP)
	// 	for _, target := range targets {
	// 		fmt.Printf("%d ", target)
	// 	}
	// 	fmt.Println()
	// }
}

// func main() {
// 	g.ParseTopo("topo.json")
// 	// topo := g.Topo[0]
// 	communities := funcs.Partition(0)

// 	GetCrossPartitionLinks(0, communities)

// 	Subset_check(0)
// 	// fmt.Println("跨分区探测对:")
// 	//
// 	//	for node, targets := range probes {
// 	//		for _, target := range targets {
// 	//			fmt.Printf("Node %d (%s) --> Node %d (%s)\n", node, topo.Points[node].IP, target, topo.Points[target].IP)
// 	//		}
// 	//	}
// }
