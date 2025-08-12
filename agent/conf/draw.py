import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import matplotlib
import json

# 创建一个空的图
G = nx.Graph()

input = open("topo.json", "r")
# 读取JSON文件
topo = json.load(input)
input.close()

for i in range(topo["point_num"]):
    G.add_node(topo["points"][str(i)]["name"])

# 添加边
for i in range(topo["link_num"]):
    points = topo["links"][i]["points"]
    for j in range(len(points)):
        # 添加边
        for k in range(len(points)):
            if k <= j:
                continue
            G.add_edge(topo["points"][str(points[j])]["name"], topo["points"][str(points[k])]["name"])

# print(G.number_of_edges())

# for font in fm.fontManager.ttflist:
#     print(font.name)

# nx.draw(G, nx.spring_layout(G), with_labels=True, node_size=1000, node_color='lightblue', edge_color='blue', font_size=13, font_family='Noto Sans CJK JP')

plt.figure(figsize=(12, 8))  # 设置画布大小
pos = nx.kamada_kawai_layout(G)  # 使用 spring 布局
nx.draw(
    G, 
    pos, 
    with_labels=True, 
    node_size=2000, 
    node_color='lightblue', 
    edge_color='blue', 
    font_size=13, 
    font_family='Songti SC'
)

# 把图形保存到文件
plt.savefig("topo.png")
