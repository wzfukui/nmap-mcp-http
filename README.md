# Nmap MCP Server

[![GitHub](https://img.shields.io/badge/GitHub-flagify--com%2Fnmap--mcp--http-blue?logo=github)](https://github.com/flagify-com/nmap-mcp-http)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)

基于 [FastMCP](https://github.com/jlowin/fastmcp) 框架开发的 Nmap 扫描服务，通过 Streamable HTTP 协议提供远程调用能力，支持 MCP (Model Context Protocol) 客户端集成。

## 功能特性

- **快速扫描** - 扫描目标主机的常用端口（约 100 个）
- **全量扫描** - 扫描全部 65535 个端口，支持服务版本检测
- **自定义扫描** - 支持任意 Nmap 命令参数
- **异步任务** - 长时间扫描自动转为后台任务，通过任务 ID 查询结果
- **Token 鉴权** - 支持 URL 参数和 Bearer Token 两种认证方式
- **结构化输出** - 快速/全量扫描返回 JSON 格式的结构化数据

## 工作机制

```
┌─────────────┐     HTTP/MCP      ┌─────────────────┐
│  MCP Client │ ◄───────────────► │  Nmap MCP Server │
└─────────────┘                   └────────┬────────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │   Task Manager  │
                                  │    (SQLite)     │
                                  └────────┬────────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │     Scanner     │
                                  │  (Nmap + XML)   │
                                  └─────────────────┘
```

1. **请求处理**：MCP Client 通过 Streamable HTTP 协议发送扫描请求
2. **任务调度**：服务器创建任务记录并存入 SQLite 数据库
3. **同步等待**：在配置的超时时间内（默认 30 秒）尝试完成扫描
4. **异步降级**：若超时未完成，任务转入后台执行，返回任务 ID 供后续查询
5. **结果解析**：Nmap 以 XML 格式输出，服务器解析后返回结构化 JSON

## 安装

### 环境要求

- Python 3.10+
- Nmap（系统需已安装）

### 安装步骤

```bash
# 克隆项目
git clone <repository-url>
cd nmap-mcp-http

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# 或 venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 生成配置文件模板
python server.py --init

# 编辑配置文件
cp config.example.json config.json
vim config.json  # 修改 token 等配置
```

## 配置

配置文件 `config.json` 示例：

```json
{
  "host": "0.0.0.0",
  "port": 3004,
  "path": "/mcp",
  "token": "your_secret_token_here",
  "sync_timeout": 30,
  "max_concurrent_tasks": 10,
  "db_path": "nmap_tasks.db",
  "nmap_path": "nmap"
}
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `host` | 监听地址 | `0.0.0.0` |
| `port` | 监听端口 | `3004` |
| `path` | MCP 服务路径 | `/mcp` |
| `token` | 鉴权令牌 | 自动生成 |
| `sync_timeout` | 同步等待超时（秒） | `30` |
| `max_concurrent_tasks` | 最大并发任务数 | `10` |
| `db_path` | SQLite 数据库路径 | `nmap_tasks.db` |
| `nmap_path` | Nmap 可执行文件路径 | `nmap` |

## 使用方法

### 启动服务

```bash
# 使用默认配置文件 (config.json)
python server.py

# 指定配置文件
python server.py -c /path/to/config.json

# 生成配置模板
python server.py --init
```

### MCP 客户端配置

服务启动后会打印 MCP 客户端配置，支持两种鉴权方式：

**方式 1：URL Token**

```json
{
  "mcpServers": {
    "nmap-scanner": {
      "name": "Nmap Scanner",
      "type": "streamableHttp",
      "description": "Nmap 端口扫描服务",
      "isActive": true,
      "baseUrl": "http://127.0.0.1:3004/mcp?token=your_token"
    }
  }
}
```

**方式 2：Bearer Token**

```json
{
  "mcpServers": {
    "nmap-scanner": {
      "name": "Nmap Scanner",
      "type": "streamableHttp",
      "description": "Nmap 端口扫描服务",
      "isActive": true,
      "baseUrl": "http://127.0.0.1:3004/mcp",
      "headers": {
        "Authorization": "Bearer your_token"
      }
    }
  }
}
```

## 可用工具

### quick_scan

快速扫描目标主机的常用端口（约 100 个）。

**参数：**
- `target` (必填): 目标 IP、域名或 CIDR 格式
- `timeout` (可选): 同步等待超时，5-300 秒

**示例：**
```json
{"target": "192.168.1.1"}
{"target": "example.com", "timeout": 60}
```

### full_scan

全量扫描目标主机的所有端口（1-65535），包含服务版本检测。

**参数：**
- `target` (必填): 目标 IP、域名或 CIDR 格式
- `timeout` (可选): 同步等待超时，5-600 秒

**示例：**
```json
{"target": "10.0.0.1", "timeout": 300}
```

### custom_scan

执行自定义 Nmap 命令。

**参数：**
- `command` (必填): Nmap 命令参数（不含 `nmap` 命令本身）
- `timeout` (可选): 同步等待超时，5-600 秒

**示例：**
```json
{"command": "-sS -p 80,443,8080 192.168.1.1"}
{"command": "-sV -sC -p 22 example.com"}
{"command": "--script vuln 192.168.1.1", "timeout": 120}
```

### get_task_status

查询扫描任务状态。

**参数：**
- `task_id` (必填): 任务 ID（UUID 格式）

**返回状态：**
- `pending`: 等待执行
- `running`: 正在扫描
- `completed`: 扫描完成
- `failed`: 扫描失败

### get_task_result

获取扫描任务的完整结果。

**参数：**
- `task_id` (必填): 任务 ID（UUID 格式）

## 返回结果示例

### 同步完成

```json
{
  "status": "completed",
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "result": {
    "target": "192.168.1.1",
    "scan_time": 2.5,
    "hosts": [
      {
        "address": "192.168.1.1",
        "status": "up",
        "ports": [
          {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "OpenSSH 8.0"
          },
          {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "version": "nginx 1.18.0"
          }
        ]
      }
    ]
  }
}
```

### 异步任务

```json
{
  "status": "pending",
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "扫描任务已提交，请使用 get_task_status 或 get_task_result 查询结果"
}
```

## 注意事项

### 安全相关

1. **Token 保护**：请务必修改默认 Token，避免未授权访问
2. **网络隔离**：建议在可信网络环境中运行，或配合防火墙使用
3. **权限控制**：本服务不限制扫描目标，请确保仅用于授权的安全测试
4. **命令注入**：`custom_scan` 工具接受任意 Nmap 参数，请评估风险

### 性能相关

1. **并发限制**：默认最多 10 个并发任务，超出时请求会被拒绝
2. **超时设置**：全量扫描耗时较长，建议使用异步任务模式
3. **资源占用**：大范围扫描（如 /16 网段）会消耗大量系统资源

### 部署建议

1. **容器化部署**：推荐使用 Docker 部署，便于隔离和管理
2. **日志监控**：建议配置日志收集，监控扫描活动
3. **定期清理**：SQLite 数据库会持续增长，建议定期清理历史任务

## 项目结构

```
nmap-mcp-http/
├── server.py          # MCP 服务器主程序
├── config.py          # 配置管理模块
├── models.py          # 数据模型定义
├── scanner.py         # Nmap 扫描器封装
├── task_manager.py    # 任务管理器（SQLite）
├── auth.py            # Token 鉴权中间件
├── test_client.py     # 测试客户端
├── config.json        # 配置文件（需自行创建）
├── config.example.json # 配置文件模板
├── requirements.txt   # Python 依赖
├── VERSION            # 版本号
├── LICENSE            # MIT 开源许可证
└── README.md          # 项目说明
```

## 贡献

欢迎提交 Issue 和 Pull Request！本项目完全开源，期待社区的参与和贡献。

## 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

Copyright (c) 2025 上海雾帜智能科技有限公司 (Shanghai Wuzhi Intelligent Technology Co., Ltd.)
