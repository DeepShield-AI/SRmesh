package funcs

import (
	"fmt"

	// "os"
	// "strconv"
	// "encoding/json"
	"controller/g"

	"gonum.org/v1/gonum/graph/path"
	"gonum.org/v1/gonum/graph/simple"
)

// Graph 结构表示一个图
type Graph struct {
	Nodes map[int][]int           // 每个节点的邻接列表(node1 -> [node2, node3, ...])
	Edges map[int]map[int]float64 // 边的权重(node1, node2 -> weight)
	K     map[int]float64         // 节点的总权重(node -> weight)
	M     float64                 // 图的总权重
}

// NewGraph 创建一个新的图
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[int][]int),
		Edges: make(map[int]map[int]float64),
		K:     make(map[int]float64),
		M:     0.0,
	}
}

func contain(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// AddEdge 添加一条边
func (graph *Graph) AddEdge(node1, node2 int, weight float64) {
	if weight == 0 {
		weight = 1.0
	}
	if !contain(graph.Nodes[node1], node2) {
		graph.Nodes[node1] = append(graph.Nodes[node1], node2)
	}

	if graph.Edges[node1] == nil {
		graph.Edges[node1] = make(map[int]float64)
	}

	graph.Edges[node1][node2] += weight

	// 更新节点的总权重
	graph.K[node1] += weight
	// 更新图的总权重
	graph.M += weight / 2
}

// ComputeModularity 计算聚合度
func (graph *Graph) ComputeModularity(communities map[int]int) float64 {
	var modularity float64

	// 计算聚合度
	for node1 := range graph.Nodes {
		for node2 := range graph.Nodes {
			if communities[node1] != communities[node2] {
				continue
			}
			var actual_weight float64
			if contain(graph.Nodes[node1], node2) {
				actual_weight = graph.Edges[node1][node2]
			}
			random_weight := graph.K[node1] * graph.K[node2] / (2 * graph.M)
			modularity += actual_weight - random_weight
		}
	}

	return modularity / (2 * graph.M)
}

func (graph *Graph) DeltaQ(t_node int, communityID int, communities map[int]int, operation string) float64 {
	var delta float64
	// fmt.Printf("t_node: %d\n", t_node)
	for _, neighbor := range graph.Nodes[t_node] {
		// fmt.Printf("neighbor: %d\n", neighbor)
		if neighbor != t_node {
			if communities[neighbor] == communityID {
				// fmt.Printf("neighbor: %d, weight: %f\n", neighbor, graph.Edges[t_node][neighbor])
				delta += graph.Edges[t_node][neighbor] / graph.M
			}
		}
	}

	var tot float64
	for node := range graph.Nodes {
		if node != t_node {
			if communities[node] == communityID {
				// fmt.Printf("node: %d, k: %f\n", node, graph.K[node])
				tot += graph.K[node]
			}
		}
	}

	// fmt.Printf("tot: %f, K: %d, M: %d\n", tot, graph.K[t_node], graph.M)
	delta -= (graph.K[t_node] * tot) / (2 * graph.M * graph.M)

	if operation == "add" {
		return delta
	}
	if operation == "remove" {
		return 0 - delta
	}
	fmt.Println("Invalid operation")
	return 0
}

// func (graph *Graph) Dijistra_path(source int) map[int][]int {
// 	// 初始化
// 	visited := make(map[int]bool)
// 	distance := make(map[int]float64)
// 	path := make(map[int][]int)

// 	for node := range graph.Nodes {
// 		visited[node] = false
// 		distance[node] = 1e10
// 		path[node] = []int{}
// 	}
// 	visited[source] = true
// 	distance[source] = 0
// 	path[source] = []int{source}

// 	for {
// 		mindistance := 1e10
// 		minnode := -1
// 		for node := range graph.Nodes {
// 			if !visited[node] && distance[node] < mindistance {
// 				mindistance = distance[node]
// 				minnode = node
// 			}
// 		}
// 		if minnode == -1 {
// 			break
// 		}
// 		visited[minnode] = true
// 		for _, neighbor := range graph.Nodes[minnode] {
// 			if !visited[neighbor] {
// 				new_distance := distance[minnode] + graph.Edges[minnode][neighbor]
// 				if new_distance < distance[neighbor] {
// 					distance[neighbor] = new_distance
// 					path[neighbor] = append(path[minnode], neighbor)
// 				}
// 			}
// 		}
// 	}
// 	fmt.Println("distance: ", distance)
// 	// fmt.Println("path: ", path)
// 	for node := range graph.Nodes {
// 		fmt.Println("---> node ", node, " path: ", path[node])
// 	}
// }

func Louvain(graph *Graph) map[int]int {
	// 初始化每个节点所在的社区，社区ID即为节点ID
	now_graph := graph
	origin_communities := make(map[int]int)
	for node := range now_graph.Nodes {
		origin_communities[node] = node
	}

	local_change := false
	communities := make(map[int]int)
	for node := range now_graph.Nodes {
		communities[node] = node
	}
	for {
		local_change = false
		// 进行多次优化迭代
		for {
			// 第一阶段：局部优化
			fmt.Println("modularity: ", now_graph.ComputeModularity(communities))
			change := now_graph.LocalOptimization(communities)
			// 如果聚合度没有增加，则停止迭代
			// break
			if !change {
				break
			}
			// 更新社区划分
			// fmt.Println("Newmodularity: ", now_graph.ComputeModularity(communities), "\n")
			local_change = true
			// communities = newCommunities
		}
		// fmt.Println("local_change: ", local_change)
		// break
		if !local_change {
			break
		}

		// 第二阶段：社区合并
		// fmt.Println("communities: ", communities)
		// var communities_map map[int]int
		var new_communities map[int]int
		// fmt.Println("Final before merge modularity: ", now_graph.ComputeModularity(communities))
		// fmt.Println("Final before merge communities: ", communities)
		_, new_communities, now_graph = now_graph.MergeCommunities(communities)
		// fmt.Println("new communities: ", communities)
		// fmt.Println("new communities_map: ", communities_map)
		// fmt.Println("Final after merge modularity: ", now_graph.ComputeModularity(new_communities))
		// 将new_communities赋值给communities
		fmt.Println("Merge ")
		// fmt.Println("now_graph: ", now_graph)
		// fmt.Println("now K: ", now_graph.K)
		// fmt.Println("now M: ", now_graph.M)
		// fmt.Println("init communities: ", communities)
		for node, community := range origin_communities {
			origin_communities[node] = communities[community]
		}
		communities = new_communities
		fmt.Println("Final modularity: ", graph.ComputeModularity(origin_communities))
		// 输出社区划分
		fmt.Println("Community Division:")
		for node, community := range origin_communities {
			fmt.Printf("Node %d -> Community %d\n", node, community)
		}
	}

	return origin_communities
}

// LocalOptimization 局部优化：每个节点尝试加入邻居的社区，以提高聚合度
func (graph *Graph) LocalOptimization(communities map[int]int) bool {
	change := false
	for node := range graph.Nodes {
		// bestModularity := graph.ComputeModularity(communities)
		bestCommunity := communities[node]
		// communities[node] = -1
		// new := graph.ComputeModularity(communities)
		// communities[node] = bestCommunity
		// old := graph.ComputeModularity(communities)
		// remove_delta_check := new - old
		// fmt.Println("remove_delta_check: ", remove_delta_check)
		remove_delta := graph.DeltaQ(node, communities[node], communities, "remove")
		// fmt.Println("Community Division:")
		// for node, community := range communities {
		// 	fmt.Printf("Node %d -> Community %d\n", node, community)
		// }
		// fmt.Printf("Node %d remove from Community %d\n", node, communities[node])
		// fmt.Println("remove_delta: ", remove_delta)
		// 计算当前节点的聚合度变化
		best_delta := -remove_delta

		// 尝试将当前节点移动到每个邻居的社区
		for _, neighbor := range graph.Nodes[node] {
			delta_q := graph.DeltaQ(node, communities[neighbor], communities, "add")
			// fmt.Printf("Node %d add to Community %d\n", node, communities[neighbor])
			// fmt.Println("delta_q: ", delta_q)
			// // 计算当前节点加入邻居社区后的聚合度变化
			// communityID := communities[node]
			// old := graph.ComputeModularity(communities)
			// communities[node] = communities[neighbor]
			// new := graph.ComputeModularity(communities)
			// fmt.Println("modularity_check: ", new - old)
			// communities[node] = communityID
			// fmt.Println("community: ", communities)

			// 如果聚合度提高，更新社区分配
			if delta_q > best_delta {
				// fmt.Println("Move")
				best_delta = delta_q
				bestCommunity = communities[neighbor]
			}
		}
		if best_delta+remove_delta > 0 {
			// 计算当前节点加入邻居社区后的聚合度变化
			// communityID := communities[node]
			// old := graph.ComputeModularity(communities)
			// communities[node] = bestCommunity
			// new := graph.ComputeModularity(communities)
			// fmt.Println("modularity_check: ", new - old)
			// communities[node] = communityID
			// fmt.Println("delta: ", best_delta + remove_delta)

			change = true
			communities[node] = bestCommunity
		}
	}
	return change
}

// MergeCommunities 合并社区：将相同社区的节点合并为一个新节点
func (graph *Graph) MergeCommunities(communities map[int]int) (map[int]int, map[int]int, *Graph) {
	// 将社区进行合并并重新计算
	communities_map := make(map[int]int) // 新社区映射(oldCommunityID -> newCommunityID)
	newNodeID := 0

	// 生成新的社区映射
	for node, community := range communities {
		if _, exists := communities_map[community]; !exists {
			communities_map[community] = newNodeID
			newNodeID++
		}
		// 将旧节点映射到新社区
		communities[node] = communities_map[community]
	}

	// 重新生成新的图
	new_graph := NewGraph()
	// fmt.Println("new communities: ", communities_map)
	// fmt.Println("communities: ", communities)

	// link := make(map[int][]int)
	// num := 0

	new_communities := make(map[int]int)
	for node, _ := range communities {
		new_nodeID := communities[node]
		if _, exists := new_communities[new_nodeID]; !exists {
			new_communities[new_nodeID] = communities[node]
		}
		for _, neighbor := range graph.Nodes[node] {
			new_neighborID := communities[neighbor]
			// num += 1
			// link[node] = append(link[node], neighbor)
			// fmt.Println("node: ", node, " neighbor: ", neighbor)
			// fmt.Println("new_nodeID: ", new_nodeID, " new_neighborID: ", new_neighborID)
			// fmt.Println("weight: ", graph.Edges[node][neighbor])
			// m := new_graph.M
			new_graph.AddEdge(new_nodeID, new_neighborID, graph.Edges[node][neighbor])
			// fmt.Println("delta_m: ", new_graph.M - m)
		}
	}
	// fmt.Println("link: ", link)
	// fmt.Println("num: ", num)
	// 返回新的社区划分
	return communities_map, new_communities, new_graph
}

func Partition(slice int) map[int]int {
	// 创建图
	graph := NewGraph()
	if slice >= len(g.Topo) {
		fmt.Println("Invalid slice index")
		return nil
	}
	topo := g.Topo[slice]
	for _, edge := range topo.Edges {
		for i := 0; i < len(edge.Node); i++ {
			for j := i + 1; j < len(edge.Node); j++ {
				graph.AddEdge(edge.Node[i], edge.Node[j], edge.Weight)
				graph.AddEdge(edge.Node[j], edge.Node[i], edge.Weight)
			}
		}
	}
	// fmt.Println("M: ", graph.M)
	// fmt.Println("K: ", graph.K)

	// 使用 Louvain 方法优化社区
	communities := Louvain(graph)

	// // 输出社区划分
	// fmt.Println("Community Division:")
	// for node, community := range communities {
	// 	fmt.Printf("Node %d -> Community %d\n", node, community)
	// }

	// fmt.Println("M: ", graph.M)
	// fmt.Println("K: ", graph.K)

	// 计算最终的聚合度
	modularity := graph.ComputeModularity(communities)
	fmt.Printf("Final Modularity: %f\n", modularity)
	return communities
}

var ShortestPaths path.AllShortest

func Dijistra_path(slice int) {
	// 创建一个有向图
	graph := simple.NewWeightedDirectedGraph(0, 0)
	if slice >= len(g.Topo) {
		fmt.Println("Invalid slice index")
		return
	}
	topo := g.Topo[slice]

	for node, _ := range topo.Points {
		graph.AddNode(simple.Node(node))
	}

	for _, edge := range topo.Edges {
		if edge.Weight == 0 {
			edge.Weight = 1.0
		}
		for i := 0; i < len(edge.Node); i++ {
			for j := i + 1; j < len(edge.Node); j++ {
				addWeightedEdge(graph, int64(edge.Node[i]), int64(edge.Node[j]), edge.Weight)
				addWeightedEdge(graph, int64(edge.Node[j]), int64(edge.Node[i]), edge.Weight)
			}
		}
	}

	ShortestPaths = path.DijkstraAllPaths(graph)
	// distance, path, _ := allPaths.From(nodeA).To(nodeB)
}

// 添加带权重的边（双向）
func addWeightedEdge(g *simple.WeightedDirectedGraph, from, to int64, weight float64) {
	g.SetWeightedEdge(g.NewWeightedEdge(simple.Node(from), simple.Node(to), weight))
}

// func main() {
// 	g.ParseTopo("topo.json")
// 	Dijistra_path(0)
// 	nodeA := 0
// 	nodeB := 5
// 	path, distance, _ := ShortestPaths.Between(int64(nodeA), int64(nodeB))
// 	fmt.Println("distance: ", distance)
// 	fmt.Println("path: ", path)

// communities := Partition(0)
// string_communities := make(map[string]int)
// for node, community := range communities {
// 	string_communities[strconv.Itoa(node)] = community
// }
// output, _ := os.Create(g.GetRoot() + "/conf/partition.json")
// defer output.Close()

// fmt.Println("communities: ", communities)

// // 将 communities 转换为 JSON 格式
// encoder := json.NewEncoder(output)
// encoder.SetIndent("", "  ") // 设置缩进格式（可选）
// err := encoder.Encode(string_communities)
// if err != nil {
// 	fmt.Println("Failed to encode JSON to file:", err)
// }
// return

// // // 解析拓扑文件
// // // g.ParseTopo()
// // graph := NewGraph()
// // g.ParseTopo()
// // // if slice >= len(g.Topo) {
// // // 	fmt.Println("Invalid slice index")
// // // 	return
// // // }
// // topo := g.Topo[0]
// // for _, edge := range topo.Edges {
// // 	for i := 0; i < len(edge.Node); i++ {
// // 		for j := i + 1; j < len(edge.Node); j++ {
// // 			// fmt.Printf("edge: %d, %d, %f\n", edge.Node[i], edge.Node[j], edge.Weight)
// // 			graph.AddEdge(edge.Node[i], edge.Node[j], edge.Weight)
// // 		}
// // 	}
// // }
// // // fmt.Println("edge: ", graph.Edges)
// // fmt.Println("node: ", graph.Nodes)
// // fmt.Println("M: ", graph.M)
// // fmt.Println("K: ", graph.K)

// // // Node 20 add to Community 19
// // // delta_q:  0.014404296875
// // // modularity_check:  -0.000244140625

// // // community:  map[0:10 1:1 2:1 3:3 4:4 5:6 6:6 7:7 8:18 9:20 10:10 11:7 12:12 13:18 14:19 15:15 16:7 17:7 18:18 19:19 20:20 21:31 22:31 23:15 24:25 25:25 26:27 27:27 28:28 29:29 30:39 31:31 32:15 33:15 34:29 35:29 36:39 37:36 38:35 39:39]
// // origin_communities := make(map[int]int)
// // origin_communities[0] = 10
// // origin_communities[1] = 1
// // origin_communities[2] = 1
// // origin_communities[3] = 3
// // origin_communities[4] = 4
// // origin_communities[5] = 6
// // origin_communities[6] = 6
// // origin_communities[7] = 7
// // origin_communities[8] = 18
// // origin_communities[9] = 20
// // origin_communities[10] = 10
// // origin_communities[11] = 7
// // origin_communities[12] = 12
// // origin_communities[13] = 18
// // origin_communities[14] = 19
// // origin_communities[15] = 15
// // origin_communities[16] = 7
// // origin_communities[17] = 7
// // origin_communities[18] = 18
// // origin_communities[19] = 19
// // origin_communities[20] = 20
// // origin_communities[21] = 31
// // origin_communities[22] = 31
// // origin_communities[23] = 15
// // origin_communities[24] = 25
// // origin_communities[25] = 25
// // origin_communities[26] = 27
// // origin_communities[27] = 27
// // origin_communities[28] = 28
// // origin_communities[29] = 29
// // origin_communities[30] = 39
// // origin_communities[31] = 31
// // origin_communities[32] = 15
// // origin_communities[33] = 15
// // origin_communities[34] = 29
// // origin_communities[35] = 29
// // origin_communities[36] = 39
// // origin_communities[37] = 36
// // origin_communities[38] = 35
// // origin_communities[39] = 39

// // // origin_communities := make(map[int]int)
// // // for node := range graph.Nodes {
// // // 	origin_communities[node] = node
// // // }

// // // 调用分区函数
// // delta := graph.DeltaQ(20, 19, origin_communities, "add")
// // fmt.Println("delta: ", delta)
// // origin_communities[20] = -1
// // old := graph.ComputeModularity(origin_communities)
// // fmt.Println("old: ", old)
// // origin_communities[20] = 19
// // modularity := graph.ComputeModularity(origin_communities)
// // fmt.Println("modularity: ", modularity)
// // fmt.Println("delta: ", modularity - old)
// }
