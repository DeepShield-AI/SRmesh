# SRmesh
Code for the paper "SRmesh: Deterministic and Efficient Diagnosis of Latency Bottleneck Links in SRv6 Networks" in IEEE ICNP 2025

### System Architecture

- **Frontend**: Web-based user interface for visualization and interaction (see `./frontend/`)
- **Controller**: Central orchestration component that manages the diagnosis process
- **Agent**: Distributed monitoring agents deployed on network nodes
- **Analyzer**: Data analysis component for processing network metrics
- **Docker Infrastructure**: Containerized deployment for easy scalability

## 🗓️ Project Timeline – 2025

| Month (2025)   | Task Description                                 | Status     |
|----------------|--------------------------------------------------|------------|
| Mid-August     | Core code implementation                         | ☐ To Do       |
| September      | Frontend development                             | ☐ To Do     |
| October        | Provide necessary utility scripts                | ☐ To Do     |
| December       | One-click deployment, testing, and optimization  | ☐ To Do     |

## 🚀 Quick Start

### Prerequisites

- Docker (version 20.10 or higher)
- Docker Compose (version 2.0 or higher)
- Linux environment with kernel version 5.4 or higher (recommended for eBPF support)
- At least 8GB RAM and 20GB disk space

### One-Click Deployment

```bash
# Clone the repository
git clone https://github.com/DeepShield-AI/SRmesh.git
cd SRmesh

# Build and deploy the entire system
cd docker
chmod +x run.sh
./run.sh

# Start the system
docker compose up -d
```

## 📋 Detailed Deployment Guide

### Method 1: Docker Compose (Recommended)

1. **Prepare the environment**
   ```bash
   # Navigate to the docker directory
   cd docker
   
   # Make scripts executable
   chmod +x run.sh
   chmod +x sh/*.sh
   ```

2. **Build Docker images**
   ```bash
   # Generate configuration files
   python3 build_yml.py
   python3 containers_sh.py
   python3 modify_conf.py
   
   # Build controller image
   docker build -t frr-go-controller -f Dockerfile.controller ..
   
   # Build agent image
   docker build -t frr-go -f Dockerfile.agent ..
   ```

3. **Deploy the system**
   ```bash
   # Start all services
   docker compose up -d
   
   # Check service status
   docker compose ps
   ```

4. **Verify deployment**
   ```bash
   # Check controller health
   docker logs controller
   
   # Verify network connectivity
   docker exec controller ss -tnlp | grep 50051
   ```

### Method 2: Manual Deployment

#### Controller Deployment

1. **Build controller**
   ```bash
   docker build -t frr-go-controller -f Dockerfile.controller .
   ```

2. **Run controller**
   ```bash
   docker run -d --name controller \
     --privileged \
     -p 50051:50051 \
     -v ./docker/sh:/app/sh \
     frr-go-controller
   ```

#### Agent Deployment

1. **Build agent**
   ```bash
   docker build -t frr-go -f Dockerfile.agent .
   ```

2. **Deploy agents on network nodes**
   ```bash
   # Deploy on each network node
   docker run -d --name agent-node-1 \
     --privileged \
     --network host \
     -v /sys/fs/bpf:/sys/fs/bpf \
     frr-go
   ```

## 🔧 Configuration

### Network Topology

The system supports custom network topologies. Configure your topology in:
- `docker/conf/topo.json` - Primary topology configuration
- `docker/conf/topo2.json` - Alternative topology configuration

Example topology configuration:
```json
{
  "nodes": [
    {
      "id": "node1",
      "type": "router",
      "ipv6": "fc00::1/64"
    },
    {
      "id": "node2", 
      "type": "router",
      "ipv6": "fc00::2/64"
    }
  ],
  "links": [
    {
      "source": "node1",
      "target": "node2",
      "latency": "10ms"
    }
  ]
}
```

### Environment Variables

Key environment variables for configuration:

| Variable | Description | Default |
|----------|-------------|---------|
| `CONTROLLER_PORT` | Controller gRPC port | 50051 |
| `LOG_LEVEL` | Logging level | INFO |
| `METRICS_INTERVAL` | Metrics collection interval | 5s |

## 🔍 Monitoring and Troubleshooting

### Health Checks

```bash
# Check all services status
docker compose ps

# View controller logs
docker logs controller -f

# Check agent connectivity
docker exec point-1 ping fc00::2

# Monitor network traffic
docker exec controller tcpdump -i any -n
```

### Common Issues

1. **Port conflicts**
   ```bash
   # Check if port 50051 is in use
   ss -tnlp | grep 50051
   
   # Kill conflicting processes if needed
   sudo kill $(sudo lsof -t -i:50051)
   ```

2. **eBPF program loading failures**
   ```bash
   # Ensure kernel version support
   uname -r
   
   # Check BPF filesystem mount
   mount | grep bpf
   ```

3. **Network connectivity issues**
   ```bash
   # Verify Docker networks
   docker network ls
   
   # Check IP routing
   docker exec controller ip route
   ```

## 🧪 Testing

### Basic Functionality Test

```bash
# Run system tests
cd docker
./test/run_tests.sh

# Manual connectivity test
docker exec controller ping6 fc00:0000:7::3
```

### Performance Benchmarking

```bash
# Network latency measurement
docker exec point-1 ./sh/point-1.sh

# Throughput testing
docker exec controller iperf -s &
docker exec point-1 iperf -c controller
```

## 🛠️ Development

### Building from Source

```bash
# Clone and build
git clone https://github.com/DeepShield-AI/SRmesh.git
cd SRmesh

# Build controller
cd controller
go build -o srmesh-controller

# Build agent
cd ../agent  
go build -o srmesh-agent
```

## 📚 Documentation

- [Controller README](./controller/README.md) - Controller component documentation
- [API Documentation](./docs/api.md) - API reference (coming soon)
- [Architecture Guide](./docs/architecture.md) - System architecture details (coming soon)

## ⚠️ System Requirements

### Recommended Requirements  
- CPU: 4+ cores
- RAM: 8GB+
- Disk: 20GB+ SSD
- Network: 10Gbps+


## 📞 Support

For questions and support:
- GitHub Issues: [https://github.com/DeepShield-AI/SRmesh/issues](https://github.com/DeepShield-AI/SRmesh/issues)

## 🔗 Citation

Comming soon.