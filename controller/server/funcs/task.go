package funcs

import (
	"context"
	"fmt"

	// "log"
	// "net"
	"encoding/json"

	"controller/pb"
	// "google.golang.org/grpc"
)

// 实现 TaskDistribution 服务
type TaskDistributionServer struct {
	pb.UnimplementedTaskDistributionServer
}

type AgentInfo struct {
	Index int
	Name  string
	IP    string
	IPv6  string
	Slice int
}

// dictionary from AgentInfo to list of destinations
// var tasks map[string]map[int][]string
var InitTasks map[int]map[int][]int
var Tasks map[int]map[int][]int

func (s *TaskDistributionServer) GetProbeDestinations(ctx context.Context, req *pb.AgentGetTaskRequest) (*pb.ControllerTaskReply, error) {
	// 实现任务下发逻辑（基于 req.AgentInfo）

	// // 将json格式的AgentInfo转换为结构体
	// agentInfo := AgentInfo{}
	// err := json.Unmarshal([]byte(req.AgentInfo), &agentInfo)

	fmt.Println("Recieve req.AgentInfo:", req.AgentInfo)
	agentInfo := AgentInfo{}
	err := json.Unmarshal([]byte(req.AgentInfo), &agentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AgentInfo: %v", err)
	}

	// for i := 0; i < len(Tasks[0]); i++ {
	// 	fmt.Println("Tasks[", i, "]: ", Tasks[0][i])
	// }

	destinations, ok := Tasks[agentInfo.Slice][agentInfo.Index-1]
	if !ok {
		return nil, fmt.Errorf("no tasks found for agent: %s %d", agentInfo.Name, agentInfo.Slice)
	}
	// destinations := []int{}
	// if agentInfo.Index == 1 {
	// 	destinations = []int{2}
	// }
	// fmt.Println("[Server: GetProbeDestinations]: find destinations:", destinations)
	ip_destinations := make([]string, len(destinations))
	for i, dest := range destinations {
		ip_destinations[i] = fmt.Sprintf("10.1.%d.%d", dest+1, agentInfo.Slice+2)
		// ip_destinations[i] = fmt.Sprintf("10.1.%d.%d fc00:0001:%x::2", dest+1, agentInfo.Slice+2, dest+1)
	}
	// fmt.Println("[Server: GetProbeDestinations]: ip_destinations:", ip_destinations)

	destinationsJSON, err := json.Marshal(ip_destinations)
	if err != nil {
		return nil, fmt.Errorf("failed to convert destinations to JSON: %v", err)
	}
	fmt.Println("destinations:", string(destinationsJSON))

	return &pb.ControllerTaskReply{
		Task: string(destinationsJSON),
	}, nil
}
