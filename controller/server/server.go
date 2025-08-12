package main

import (
	// "context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"controller/funcs"
	"controller/g"
	"controller/pb"

	"google.golang.org/grpc"
)

func main() {
	fmt.Println("服务端启动中...")
	g.ParseTopo("topo2.json")
	funcs.InitTasks = make(map[int]map[int][]int)
	funcs.Tasks = make(map[int]map[int][]int)
	for i := 0; i < len(g.Topo); i++ {
		if funcs.InitTasks[i] == nil {
			funcs.InitTasks[i] = make(map[int][]int)
		}
		// 为每个切片分区
		communities := funcs.Partition(i)
		community_nodes := make(map[int][]int)
		for node, community := range communities {
			community_nodes[community] = append(community_nodes[community], node)
		}
		// fmt.Println("map : ", community_nodes)
		for _, nodes := range community_nodes {
			// fullmesh
			for j := 0; j < len(nodes); j++ {
				for k := j + 1; k < len(nodes); k++ {
					funcs.InitTasks[i][nodes[j]] = append(funcs.InitTasks[i][nodes[j]], nodes[k])
					funcs.InitTasks[i][nodes[k]] = append(funcs.InitTasks[i][nodes[k]], nodes[j])
				}
			}
		}

		// 获取跨分区探测对
		funcs.GetCrossPartitionLinks(i, communities)
		// fmt.Println("InitTasks:", funcs.InitTasks[i])

		if funcs.Tasks[i] == nil {
			funcs.Tasks[i] = make(map[int][]int)
		}
		funcs.Subset_check(i)
	}

	// fmt.Println("InitTasks:", funcs.InitTasks)
	for i := 0; i < len(g.Topo); i++ {
		fmt.Println("Slice", i, "的任务分配:")
		for node, targets := range funcs.Tasks[i] {
			fmt.Printf("节点 %d ---> ", node)
			for _, target := range targets {
				fmt.Printf("%d ", target)
			}
			fmt.Println()
		}
	}

	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}

	grpcServer := grpc.NewServer()

	// 注册服务
	pb.RegisterTaskDistributionServer(grpcServer, &funcs.TaskDistributionServer{})
	pb.RegisterProbeStatusServer(grpcServer, &funcs.ProbeStatusServer{})
	pb.RegisterProbeDataServer(grpcServer, &funcs.ProbeDataServer{})

	fmt.Println("服务端已启动，监听端口 50051")
	if err := grpcServer.Serve(lis); err != nil {
		fmt.Println("启动失败: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)


	for {
		select {
		case <-sig: // 如果接收到退出信号
			fmt.Println("[func:main] Received interrupt signal, shutting down...")
			grpcServer.GracefulStop() // 优雅地关闭 gRPC 服务器
			return
		}
	}
}

// // 实现 TaskDistribution 服务
// type taskDistributionServer struct {
// 	pb.UnimplementedTaskDistributionServer
// }

// func (s *taskDistributionServer) GetProbeDestinations(ctx context.Context, req *pb.AgentGetTaskRequest) (*pb.ControllerTaskReply, error) {
// 	// TODO: 实现任务下发逻辑（基于 req.AgentInfo）
// 	return &pb.ControllerTaskReply{
// 		Task: "{}",
// 	}, nil
// }

// // 实现 ProbeStatus 服务
// type probeStatusServer struct {
// 	pb.UnimplementedProbeStatusServer
// }

// func (s *probeStatusServer) ReportProbeStatus(ctx context.Context, req *pb.AgentUploadReportRequest) (*pb.ControllerResponseReply, error) {
// 	// TODO: 实现探针状态上报逻辑（基于 req.Report）
// 	return &pb.ControllerResponseReply{
// 		Resonse: "ok",
// 	}, nil
// }

// // 实现 ProbeData 服务
// type probeDataServer struct {
// 	pb.UnimplementedProbeDataServer
// }

// func (s *probeDataServer) ReportProbeData(ctx context.Context, req *pb.AgentUploadDataRequest) (*pb.ControllerResponseReply, error) {
// 	// TODO: 实现探针数据上报逻辑（基于 req.Data）
// 	return &pb.ControllerResponseReply{
// 		Resonse: "ok",
// 	}, nil
// }
