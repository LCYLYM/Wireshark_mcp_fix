#!/usr/bin/env python3
"""
使用 Wireshark MCP 的简单示例
演示如何通过 MCP 协议与 Wireshark 进行交互
"""

import json

def demonstrate_wireshark_mcp():
    """演示 Wireshark MCP 的基本功能"""
    
    print("🌟 Wireshark MCP 使用示例")
    print("=" * 40)
    
    # 注意：这是一个演示示例，实际使用时需要有真实的 tshark 环境
    
    print("1. 📡 列出网络接口")
    print("   调用: list_interfaces()")
    print("   返回: 所有可用的网络接口列表")
    print()
    
    print("2. 📄 分析 PCAP 文件")
    print("   调用: analyze_pcap('/path/to/capture.pcap', filter='tcp port 80', max_packets=100)")
    print("   返回: 结构化的 JSON 数据包分析结果")
    print()
    
    print("3. 🔍 提取特定字段")
    print("   调用: extract_fields('/path/to/capture.pcap', ['ip.src', 'ip.dst'], max_packets=1000)")
    print("   返回: 字段统计分析，包括频率排行")
    print()
    
    print("4. 🚨 错误分析")
    print("   调用: analyze_errors('/path/to/capture.pcap', error_type='tcp', max_packets=5000)")
    print("   返回: TCP 错误和异常情况的详细分析")
    print()
    
    print("5. 📊 协议统计")
    print("   调用: get_packet_statistics('/path/to/capture.pcap')")
    print("   返回: I/O 统计、会话统计和端点统计")
    print()
    
    # 示例 JSON 输出格式
    example_output = {
        "status": "success",
        "metadata": {
            "timestamp": "2024-01-01T12:00:00",
            "tshark_version": "TShark 4.0.0",
            "file_path": "/path/to/capture.pcap",
            "max_packets": 100
        },
        "statistics": {
            "total_packets": 85,
            "returned_packets": 85,
            "truncated": False
        },
        "data": [
            {
                "_index": "packets-2024-01-01",
                "_type": "pcap_file",
                "_score": None,
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.time": "Jan  1, 2024 12:00:00.123456000 UTC"
                        },
                        "ip": {
                            "ip.src": "192.168.1.100",
                            "ip.dst": "8.8.8.8"
                        },
                        "tcp": {
                            "tcp.srcport": "54321",
                            "tcp.dstport": "80"
                        }
                    }
                }
            }
        ]
    }
    
    print("📋 示例输出格式:")
    print(json.dumps(example_output, ensure_ascii=False, indent=2))
    print()
    
    print("🔧 配置 MCP 客户端:")
    mcp_config = {
        "mcpServers": {
            "wireshark": {
                "command": "python",
                "args": ["/path/to/wireshark_mcp.py", "--transport", "stdio"],
                "env": {
                    "PATH": "/usr/local/bin:/usr/bin:/bin"
                }
            }
        }
    }
    print(json.dumps(mcp_config, ensure_ascii=False, indent=2))
    print()
    
    print("✨ 特性:")
    features = [
        "✅ 无硬编码数据 - 所有结果来自真实的 tshark 命令",
        "✅ 完整错误处理 - 详细的错误信息和建议",
        "✅ 参数验证 - 防止路径遍历和命令注入攻击",
        "✅ 结构化输出 - 便于 LLM 理解和处理的 JSON 格式",
        "✅ 多传输协议 - 支持 SSE、stdio 和 HTTP",
        "✅ 实时分析 - 支持实时数据包捕获和分析",
        "✅ 智能过滤 - 支持 BPF 和 Wireshark 显示过滤器",
        "✅ 协议分析 - 深度分析特定网络协议"
    ]
    
    for feature in features:
        print(f"   {feature}")

if __name__ == "__main__":
    demonstrate_wireshark_mcp()