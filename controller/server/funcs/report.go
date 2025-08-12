package funcs

import (
	"context"
	// "fmt"
	// "log"
	// "net"

	"controller/pb"
	// "google.golang.org/grpc"
)

// 实现 ProbeStatus 服务
type ProbeStatusServer struct {
	pb.UnimplementedProbeStatusServer
}

func (s *ProbeStatusServer) ReportProbeStatus(ctx context.Context, req *pb.AgentUploadReportRequest) (*pb.ControllerResponseReply, error) {
	// TODO: 实现探针状态上报逻辑（基于 req.Report）
	return &pb.ControllerResponseReply{
		Resonse: "ok",
	}, nil
}

// 实现 ProbeData 服务
type ProbeDataServer struct {
	pb.UnimplementedProbeDataServer
}

func (s *ProbeDataServer) ReportProbeData(ctx context.Context, req *pb.AgentUploadDataRequest) (*pb.ControllerResponseReply, error) {
	// TODO: 实现探针数据上报逻辑（基于 req.Data）
	return &pb.ControllerResponseReply{
		Resonse: "ok",
	}, nil
}