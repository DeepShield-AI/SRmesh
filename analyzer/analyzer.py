#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pandas as pd
import numpy as np
import networkx as nx
from collections import defaultdict
import glob
import os
import sys
from scipy.optimize import nnls

class NetworkAnalyzer:
    def __init__(self, topo_file="../docker/conf/topo.json", csv_dir="../agent/csv/"):
        """
        初始化网络分析器
        :param topo_file: 拓扑文件路径
        :param csv_dir: CSV文件目录
        """
        self.topo_file = topo_file
        self.csv_dir = csv_dir
        self.graph = nx.Graph()
        self.ip_to_point = {}
        self.point_to_name = {}
        self.link_delays = {}
        self.bottleneck_threshold = 100  # 默认瓶颈阈值100ms
        
    def load_topology(self):
        """读取拓扑配置文件"""
        print("[INFO] Loading topology...")
        try:
            with open(self.topo_file, 'r', encoding='utf-8') as f:
                topo_data = json.load(f)[0]  # 取第一个拓扑
                
            # 构建点到名称的映射
            for point_id, point_info in topo_data["points"].items():
                self.point_to_name[int(point_id)] = point_info["name"]
                # 构建IP到点的映射 (10.1.{point+1}.2)
                ip = f"10.1.{int(point_id)+1}.2"
                self.ip_to_point[ip] = int(point_id)
                
            # 构建网络图
            for link in topo_data["links"]:
                point1, point2 = link["points"]
                self.graph.add_edge(point1, point2, ip=link["IP"])
                
            print(f"[INFO] Loaded {len(self.point_to_name)} nodes and {len(topo_data['links'])} links")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to load topology: {e}")
            return False
    
    def find_all_paths(self, source, target, max_paths=3):
        """
        找到两点间的最短路径，只在最小跳数路径中选择
        :param source: 源节点
        :param target: 目标节点  
        :param max_paths: 最大路径数
        :return: 路径列表
        """
        try:
            # 先找最短路径长度
            shortest_length = nx.shortest_path_length(self.graph, source, target)
            
            # 找到所有最短长度的路径
            all_shortest_paths = []
            for path in nx.all_simple_paths(self.graph, source, target, cutoff=shortest_length):
                if len(path) == shortest_length + 1:  # path长度 = 跳数 + 1
                    all_shortest_paths.append(path)
            
            # 限制返回的路径数量
            if len(all_shortest_paths) > max_paths:
                all_shortest_paths = all_shortest_paths[:max_paths]
                
            return all_shortest_paths
        except nx.NetworkXNoPath:
            return []
    
    def load_csv_data(self):
        """读取CSV文件数据"""
        print("[INFO] Loading CSV data...")
        csv_files = glob.glob(os.path.join(self.csv_dir, "pingLog*.csv"))
        
        if not csv_files:
            print("[WARNING] No CSV files found")
            return pd.DataFrame()
            
        # 合并所有CSV文件
        dataframes = []
        for file in csv_files:
            try:
                df = pd.read_csv(file)
                dataframes.append(df)
            except Exception as e:
                print(f"[WARNING] Failed to read {file}: {e}")
                
        if dataframes:
            combined_df = pd.concat(dataframes, ignore_index=True)
            print(f"[INFO] Loaded {len(combined_df)} probe records from {len(csv_files)} files")
            return combined_df
        else:
            return pd.DataFrame()
    
    def analyze_probe_results(self, df):
        """分析探测结果，计算平均延迟"""
        print("[INFO] Analyzing probe results...")
        
        df_filtered = df[
            (df['AvgDelay'] > 0) 
        ].copy()
        
        if df_filtered.empty:
            print("[WARNING] No valid probe data found")
            return {}
            
        # 按源-目的分组，计算平均延迟
        probe_results = {}
        grouped = df_filtered.groupby(['Source', 'Destination'])
        
        for (src_ip, dst_ip), group in grouped:
            if src_ip in self.ip_to_point and dst_ip in self.ip_to_point:
                src_point = self.ip_to_point[src_ip]
                dst_point = self.ip_to_point[dst_ip]
                
                # 计算平均延迟（去除异常值）
                delays = group['AvgDelay'].values
                # 使用四分位数去除异常值
                q25, q75 = np.percentile(delays, [25, 75])
                iqr = q75 - q25
                lower_bound = q25 - 1.5 * iqr
                upper_bound = q75 + 1.5 * iqr
                
                valid_delays = delays[(delays >= lower_bound) & (delays <= upper_bound)]
                
                if len(valid_delays) > 0:
                    avg_delay = np.mean(valid_delays)
                    probe_results[(src_point, dst_point)] = {
                        'avg_delay': avg_delay,
                        'sample_count': len(valid_delays),
                        'min_delay': np.min(valid_delays),
                        'max_delay': np.max(valid_delays)
                    }
                    
        print(f"[INFO] Analyzed {len(probe_results)} valid probe pairs")
        return probe_results
    
    def greedy_grouped_inference(self, constraints, epsilon=10.0):
        """
        基于分组贪心策略的多路径延迟推断算法实现，优化目标为最少异常链路。

        :param constraints: List of dicts {'paths': List[List[link_id]], 'delay': float}
                            每个约束的 'paths' 为候选路径列表，若仅有一条则为确定性约束
        :param epsilon: 分组及误差阈值
        :return: tuple (selected_paths, link_delays)
                 selected_paths: List of chosen path (List[link_id]) for each constraint
                 link_delays: dict mapping link_id 到推断的延迟值
        """
        print(f"[DEBUG] Starting inference with {len(constraints)} constraints, epsilon={epsilon}")
        
        # 区分确定性与不确定性约束，并标记确定性约束的选项
        deterministic = []
        uncertain = []
        for c in constraints:
            if len(c['paths']) == 1:
                c['selected'] = 0
                deterministic.append(c)
            else:
                uncertain.append(c)
        
        print(f"[DEBUG] {len(deterministic)} deterministic, {len(uncertain)} uncertain constraints")

        # 收集所有链路并建立索引
        all_links = set()
        for c in constraints:
            for p in c['paths']:
                all_links.update(p)
        link_list = list(all_links)
        link_index = {l: i for i, l in enumerate(link_list)}
        n_links = len(link_list)

        # 初始化链路延迟估计
        link_delays = np.zeros(n_links)

        updated = True
        # 迭代处理不确定性约束
        while updated:
            updated = False
            new_deterministic = []

            for c in uncertain:
                if 'selected' in c:
                    continue
                # 计算每条候选路径的当前延迟预测
                estimates = [sum(link_delays[link_index[l]] for l in p) for p in c['paths']]

                # 聚类分组
                groups = []  # 每组存 {'indices': [idx], 'rep': float}
                for idx, val in enumerate(estimates):
                    placed = False
                    for g in groups:
                        if abs(val - g['rep']) <= epsilon:
                            g['indices'].append(idx)
                            g['rep'] = np.mean([estimates[i] for i in g['indices']])
                            placed = True
                            break
                    if not placed:
                        groups.append({'indices': [idx], 'rep': val})

                # 计算各组诱导误差，优化目标为最少异常链路
                best_group = None
                best_score = float('inf')
                
                for g in groups:
                    error = abs(c['delay'] - g['rep'])
                    # 放宽误差阈值，重点关注异常链路数量
                    if error <= epsilon * 2:  # 放宽误差容忍度
                        # 对于可接受的误差，计算该选择会产生的异常链路数
                        test_path = c['paths'][g['indices'][0]]
                        
                        # 模拟选择该路径后的链路延迟
                        temp_deterministic = deterministic + [{'paths': [test_path], 'delay': c['delay'], 'selected': 0}]
                        
                        # 重新构建并求解线性系统
                        m = len(temp_deterministic)
                        A = np.zeros((m, n_links))
                        b = np.zeros(m)
                        for i, tc in enumerate(temp_deterministic):
                            path = tc['paths'][tc['selected']]
                            for link in path:
                                A[i, link_index[link]] = 1
                            b[i] = tc['delay']
                        
                        try:
                            x, _ = nnls(A, b)
                            
                            # 计算异常链路数量
                            # 使用更严格的异常标准：超过平均延迟2倍的链路
                            avg_delay = np.mean(x[x > 0]) if np.any(x > 0) else 10.0
                            threshold = max(avg_delay * 2, 30.0)  # 至少30ms作为异常阈值
                            abnormal_count = np.sum(x > threshold)
                            
                            # 额外惩罚非常高的延迟（>100ms）
                            very_high_count = np.sum(x > 100.0)
                            
                            # 评分：优先减少异常链路，其次考虑误差
                            score = abnormal_count * 100.0 + very_high_count * 200.0 + error
                            
                            if score < best_score:
                                best_score = score
                                best_group = g
                                
                        except Exception:
                            # 如果求解失败，给一个高分惩罚
                            score = 1000.0 + error
                            if score < best_score:
                                best_score = score
                                best_group = g

                # 如果找到可接受的组，选择最优的
                if best_group is not None:
                    sel = best_group['indices'][0]
                    c['selected'] = sel
                    updated = True
                    new_deterministic.append(c)
                    print(f"[DEBUG] Selected path with score {best_score:.2f} (minimizing abnormal links)")
                else:
                    # 如果没有找到可接受的组，选择误差最小的
                    min_error_group = min(groups, key=lambda g: abs(c['delay'] - g['rep']))
                    if abs(c['delay'] - min_error_group['rep']) <= epsilon * 3:  # 进一步放宽
                        sel = min_error_group['indices'][0]
                        c['selected'] = sel
                        updated = True
                        new_deterministic.append(c)
                        print(f"[DEBUG] Fallback: selected path with error {abs(c['delay'] - min_error_group['rep']):.2f}ms")

            # 若有新增确定性，重解线性系统
            if new_deterministic:
                deterministic.extend(new_deterministic)
                
                # 重新构建线性系统
                m = len(deterministic)
                A = np.zeros((m, n_links))
                b = np.zeros(m)
                for i, c in enumerate(deterministic):
                    path = c['paths'][c['selected']]
                    for link in path:
                        A[i, link_index[link]] = 1
                    b[i] = c['delay']
                
                print(f"[DEBUG] Solving updated linear system: A shape={A.shape}, b shape={b.shape}")
                print(f"[DEBUG] Matrix rank: {np.linalg.matrix_rank(A)}, delay range: {np.min(b):.2f} - {np.max(b):.2f}ms")
                
                try:
                    x, _ = nnls(A, b)
                    print(f"[DEBUG] Solution range: {np.min(x):.2f} - {np.max(x):.2f}ms")
                    
                    # 统计当前瓶颈链路
                    current_bottlenecks = np.sum(x > 50.0)
                    print(f"[DEBUG] Current solution has {current_bottlenecks} bottleneck links (>50ms)")
                    
                    link_delays = x
                except Exception:
                    print("[WARNING] Linear system solving failed, keeping previous solution")

        # 对剩余未选的约束，采用均值或最接近误差最小的候选路径
        for c in uncertain:
            if 'selected' in c:
                continue
            estimates = [sum(link_delays[link_index[l]] for l in p) for p in c['paths']]
            mean_val = np.mean(estimates)
            if abs(c['delay'] - mean_val) <= epsilon:
                choice = min(range(len(estimates)), key=lambda i: abs(estimates[i] - mean_val))
            else:
                choice = min(range(len(estimates)), key=lambda i: abs(estimates[i] - c['delay']))
            c['selected'] = choice

        # 最终求解所有约束的线性系统
        m = len(constraints)
        A = np.zeros((m, n_links))
        b = np.zeros(m)
        
        for i, c in enumerate(constraints):
            path = c['paths'][c['selected']]
            for link in path:
                A[i, link_index[link]] = 1
            b[i] = c['delay']
        
        print(f"[DEBUG] Final linear system: A shape={A.shape}, b shape={b.shape}")
        print(f"[DEBUG] Final matrix rank: {np.linalg.matrix_rank(A)}, delay range: {np.min(b):.2f} - {np.max(b):.2f}ms")
        
        try:
            x, _ = nnls(A, b)
            print(f"[DEBUG] Final solution range: {np.min(x):.2f} - {np.max(x):.2f}ms")
            
            link_delays = x
                
        except Exception as e:
            print(f"[ERROR] Final linear system solving failed: {e}")
            # 使用简单平均分配作为后备方案
            link_usage_count = np.zeros(n_links)
            link_delay_sum = np.zeros(n_links)
            
            for i, c in enumerate(constraints):
                path = c['paths'][c['selected']]
                path_length = len(path)
                avg_delay_per_link = c['delay'] / path_length
                for link in path:
                    link_usage_count[link_index[link]] += 1
                    link_delay_sum[link_index[link]] += avg_delay_per_link
            
            for i in range(n_links):
                if link_usage_count[i] > 0:
                    link_delays[i] = link_delay_sum[i] / link_usage_count[i]
            
            print(f"[DEBUG] Fallback solution range: {np.min(link_delays):.2f} - {np.max(link_delays):.2f}ms")

        # 收集输出结果
        selected_paths = [c['paths'][c['selected']] for c in constraints]
        link_delay_dict = {l: float(link_delays[link_index[l]]) for l in link_list}
        return selected_paths, link_delay_dict

    def estimate_link_delays(self, probe_results):
        """推估每条链路的延迟 - 使用多路径贪心分组推断算法"""
        print("[INFO] Estimating link delays using multi-path inference...")
        
        # 准备约束条件
        constraints = []
        
        for (p1, p2), result in probe_results.items():
            all_paths = self.find_all_paths(p1, p2)
            
            if all_paths:
                # 将路径转换为链路列表
                path_links_list = []
                for path in all_paths:
                    path_links = []
                    for i in range(len(path) - 1):
                        link = tuple(sorted([path[i], path[i+1]]))
                        path_links.append(link)
                    path_links_list.append(path_links)
                
                # 添加约束
                constraint = {
                    'paths': path_links_list,
                    'delay': result['avg_delay'],
                    'src_dst': (p1, p2)
                }
                constraints.append(constraint)
                
                # 显示路径信息
                p1_name = self.point_to_name[p1]
                p2_name = self.point_to_name[p2]
                print(f"  {p1_name} <-> {p2_name} ({len(all_paths)} paths, delay: {result['avg_delay']:.2f}ms):")
                for i, path in enumerate(all_paths):
                    path_names = [self.point_to_name[p] for p in path]
                    print(f"    Path {i+1}: {' -> '.join(path_names)}")
        
        if not constraints:
            print("[WARNING] No valid constraints found")
            return {}
        
        # 使用贪心分组推断算法
        try:
            selected_paths, link_delays = self.greedy_grouped_inference(constraints, epsilon=10.0)
            
            print(f"\n[INFO] Selected paths and estimated link delays:")
            for i, constraint in enumerate(constraints):
                src, dst = constraint['src_dst']
                selected_path_idx = constraint['selected']
                selected_path = constraint['paths'][selected_path_idx]
                
                # 重建节点路径用于显示
                node_path = []
                current_nodes = set([src])
                for link in selected_path:
                    p1, p2 = link
                    if p1 in current_nodes:
                        node_path.append(p1)
                        current_nodes = {p2}
                    else:
                        node_path.append(p2)
                        current_nodes = {p1}
                node_path.append(list(current_nodes)[0])
                
                path_names = [self.point_to_name[p] for p in node_path]
                src_name = self.point_to_name[src]
                dst_name = self.point_to_name[dst]
                print(f"    {src_name} -> {dst_name}: {' -> '.join(path_names)} (Path {selected_path_idx + 1})")
            
            print(f"\n[INFO] Estimated link delays:")
            for link, delay in link_delays.items():
                if delay > 0:  # 只显示有延迟的链路
                    p1, p2 = link
                    print(f"    {self.point_to_name[p1]} <-> {self.point_to_name[p2]}: {delay:.2f}ms")
            
            return link_delays
            
        except Exception as e:
            print(f"[ERROR] Multi-path inference failed: {e}")
            return {}
    
    def detect_bottlenecks(self, link_delays, threshold=None):
        """检测瓶颈链路"""
        if threshold is None:
            threshold = self.bottleneck_threshold
            
        print(f"\n[INFO] Detecting bottleneck links (threshold: {threshold}ms)...")
        
        bottlenecks = []
        for link, delay in link_delays.items():
            if delay > threshold:
                p1, p2 = link
                bottlenecks.append({
                    'link': f"{self.point_to_name[p1]} <-> {self.point_to_name[p2]}",
                    'delay': delay,
                    'severity': 'HIGH' if delay > threshold * 2 else 'MEDIUM'
                })
        
        # 按延迟排序
        bottlenecks.sort(key=lambda x: x['delay'], reverse=True)
        
        if bottlenecks:
            print(f"[ALERT] Found {len(bottlenecks)} bottleneck links:")
            for bottleneck in bottlenecks:
                print(f"  🚨 {bottleneck['link']}: {bottleneck['delay']:.2f}ms [{bottleneck['severity']}]")
        else:
            print("[INFO] No bottleneck links detected")
            
        return bottlenecks
    
    def generate_report(self, probe_results, link_delays, bottlenecks):
        """生成分析报告"""
        print("\n" + "="*60)
        print("NETWORK DELAY ANALYSIS REPORT")
        print("="*60)
        
        print(f"\n📊 SUMMARY:")
        print(f"  • Total probe pairs analyzed: {len(probe_results)}")
        print(f"  • Total links estimated: {len(link_delays)}")
        print(f"  • Bottleneck links found: {len(bottlenecks)}")
        
        if link_delays:
            delays = list(link_delays.values())
            print(f"\n📈 LINK DELAY STATISTICS:")
            print(f"  • Average link delay: {np.mean(delays):.2f}ms")
            print(f"  • Maximum link delay: {np.max(delays):.2f}ms")
            print(f"  • Minimum link delay: {np.min(delays):.2f}ms")
            print(f"  • Standard deviation: {np.std(delays):.2f}ms")
            
        if bottlenecks:
            print(f"\n🚨 MOST SEVERE BOTTLENECK:")
            most_severe = bottlenecks[0]
            print(f"  • {most_severe['link']}: {most_severe['delay']:.2f}ms [{most_severe['severity']}]")
    
    def run_analysis(self, bottleneck_threshold=100):
        """运行完整分析"""
        self.bottleneck_threshold = bottleneck_threshold
        
        print("🔍 Starting Network Delay Analysis...")
        print("="*50)
        
        # 1. 加载拓扑
        if not self.load_topology():
            return False
            
        # 2. 加载CSV数据
        df = self.load_csv_data()
        if df.empty:
            print("[ERROR] No valid CSV data found")
            return False
            
        # 3. 分析探测结果
        probe_results = self.analyze_probe_results(df)
        if not probe_results:
            print("[ERROR] No valid probe results")
            return False
            
        # 4. 估算链路延迟
        link_delays = self.estimate_link_delays(probe_results)
        if not link_delays:
            print("[ERROR] Failed to estimate link delays")
            return False
            
        # 5. 检测瓶颈
        bottlenecks = self.detect_bottlenecks(link_delays, bottleneck_threshold)
        
        # 6. 生成报告
        self.generate_report(probe_results, link_delays, bottlenecks)
        
        return True

def main():
    """主函数"""
    # 默认参数
    threshold = 100
    
    # 解析命令行参数
    if len(sys.argv) > 1:
        try:
            threshold = float(sys.argv[1])
            print(f"[INFO] Using bottleneck threshold: {threshold}ms")
        except ValueError:
            print(f"[WARNING] Invalid threshold value, using default: {threshold}ms")
    
    # 创建分析器并运行
    analyzer = NetworkAnalyzer()
    success = analyzer.run_analysis(threshold)
    
    if success:
        print("\n✅ Analysis completed successfully!")
    else:
        print("\n❌ Analysis failed!")
        return 1
        
    return 0

if __name__ == "__main__":
    exit(main())
