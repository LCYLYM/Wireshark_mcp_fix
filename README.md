# Wireshark MCP

Wireshark MCP 是一个基于 Model Context Protocol (MCP) 的服务器，允许 AI 助手通过 tshark 命令行工具与 Wireshark 进行交互。它将 Wireshark/tshark 的强大功能与大语言模型(LLM)的智能分析能力相结合，实现智能化的网络数据分析。

## 功能特性

### 核心功能
- **实时数据包捕获**: 支持在指定网络接口上进行实时数据包捕获
- **数据包文件分析**: 分析 pcap/pcapng 格式的数据包文件
- **智能过滤**: 支持 BPF 和 Wireshark 显示过滤器表达式
- **协议分析**: 针对特定协议进行深度分析
- **错误检测**: 自动检测和分析网络传输中的各种错误
- **字段提取**: 从数据包中提取特定字段并进行统计分析
- **统计报告**: 生成详细的数据包统计和分析报告

### MCP 集成特性
- **标准化 API**: 遵循 Model Context Protocol 规范
- **多传输协议**: 支持 SSE、stdio 和 streamable-HTTP 传输
- **结构化输出**: 所有输出均为结构化 JSON 格式
- **错误处理**: 完善的错误处理和用户友好的错误信息
- **实时 API**: 所有数据都通过真实的 tshark 命令获取，无硬编码数据

## 系统要求

- Python 3.9+
- Wireshark/tshark (必须安装并在 PATH 中可用)
- MCP SDK 1.15.0+

## 安装

1. 确保已安装 Wireshark 和 tshark:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install wireshark tshark
   
   # macOS (使用 Homebrew)
   brew install wireshark
   
   # Windows: 下载并安装 Wireshark 官方安装包
   ```

2. 安装 Python 依赖:
   ```bash
   pip install -r requirements.txt
   ```

## 使用方法

### 基本启动
```bash
# 使用默认设置启动 (SSE 传输，端口 3000)
python wireshark_mcp.py

# 指定 tshark 路径
python wireshark_mcp.py --tshark-path /usr/local/bin/tshark

# 指定主机和端口
python wireshark_mcp.py --host 0.0.0.0 --port 8080

# 使用 stdio 传输 (适用于直接集成)
python wireshark_mcp.py --transport stdio
```

### MCP 客户端配置

对于支持 MCP 的客户端，使用以下配置:

**SSE 传输**:
- 名称: `wireshark`
- 类型: `服务器发送事件 (sse)`
- URL: `http://127.0.0.1:3000/sse`

**Streamable HTTP 传输**:
- 名称: `wireshark`
- 类型: `HTTP`
- URL: `http://127.0.0.1:3000/mcp`

## 可用工具

### 1. list_interfaces()
列出所有可用的网络接口
- **返回**: 接口名称和描述的列表

### 2. capture_live(interface, duration=10, filter="", max_packets=100)
实时数据包捕获
- **interface**: 网络接口名称
- **duration**: 捕获时长（秒）
- **filter**: BPF 过滤器表达式
- **max_packets**: 最大数据包数

### 3. analyze_pcap(file_path, filter="", max_packets=100)
分析 pcap 文件
- **file_path**: pcap/pcapng 文件路径
- **filter**: Wireshark 显示过滤器
- **max_packets**: 最大分析数据包数

### 4. get_protocols()
获取支持的协议列表
- **返回**: 可用协议名称列表

### 5. get_packet_statistics(file_path, filter="")
获取数据包统计信息
- **file_path**: pcap/pcapng 文件路径
- **filter**: 可选过滤器表达式

### 6. extract_fields(file_path, fields, filter="", max_packets=5000)
提取特定字段并统计
- **file_path**: pcap/pcapng 文件路径
- **fields**: 字段名称列表 (如 ["ip.src", "ip.dst"])
- **filter**: 可选过滤器表达式
- **max_packets**: 最大分析数据包数

### 7. analyze_protocols(file_path, protocol="", max_packets=100)
分析特定协议
- **file_path**: pcap/pcapng 文件路径
- **protocol**: 协议名称 (如 "http", "tcp")
- **max_packets**: 最大分析数据包数

### 8. analyze_errors(file_path, error_type="all", max_packets=5000)
分析网络错误
- **file_path**: pcap/pcapng 文件路径
- **error_type**: 错误类型 ("all", "malformed", "tcp", "retransmission", "duplicate_ack", "lost_segment")
- **max_packets**: 最大分析数据包数

## 输出格式

所有工具都返回结构化的 JSON 格式，包含:
- **status**: 操作状态 ("success", "error", "no_data")
- **metadata**: 元数据信息 (时间戳、文件路径、tshark 版本等)
- **data**: 主要数据内容
- **statistics**: 统计信息 (如适用)
- **error**: 错误信息 (如适用)

## 开发说明

### 架构特点
- **无硬编码数据**: 所有数据都通过真实的 tshark 命令获取
- **真实 API 请求**: 每次调用都执行实际的网络分析操作
- **完整错误处理**: 包含详细的错误信息和建议
- **结构化输出**: 便于 LLM 理解和处理的 JSON 格式

### 代码结构
- `WiresharkMCP`: 核心类，封装所有 tshark 操作
- `create_mcp_server()`: 创建和配置 MCP 服务器
- 工具函数: 通过 `@mcp.tool()` 装饰器暴露给 MCP 客户端

## 许可证

Apache License 2.0

## 贡献

欢迎提交 Issue 和 Pull Request 来改进此项目。

## 特别感谢

- [Model Context Protocol](https://modelcontextprotocol.io/) 项目
- [Wireshark](https://www.wireshark.org/) 网络协议分析器
- Python MCP SDK 开发团队