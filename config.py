"""
Nmap MCP Server 配置模块
"""
import os
import json
import secrets
import argparse
from dataclasses import dataclass, asdict
from pathlib import Path


def generate_token() -> str:
    """生成随机 Token"""
    return secrets.token_urlsafe(32)


# 默认配置文件路径（程序同级目录）
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.json"
EXAMPLE_CONFIG_PATH = Path(__file__).parent / "config.example.json"


@dataclass
class Config:
    """服务器配置"""
    # 服务器设置
    host: str = "0.0.0.0"
    port: int = 3004
    path: str = "/mcp"

    # 鉴权设置
    token: str = ""  # 访问令牌，为空则自动生成

    # 任务设置
    sync_timeout: int = 30  # 同步等待超时（秒）
    max_concurrent_tasks: int = 10  # 最大并发任务数

    # 数据库设置
    db_path: str = "nmap_tasks.db"

    # Nmap 设置
    nmap_path: str = "nmap"  # nmap 可执行文件路径

    @classmethod
    def from_json_file(cls, config_path: str | Path) -> "Config":
        """从 JSON 文件加载配置"""
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {config_path}")

        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 创建配置实例
        config = cls(
            host=data.get("host", "0.0.0.0"),
            port=data.get("port", 3004),
            path=data.get("path", "/mcp"),
            token=data.get("token", ""),
            sync_timeout=data.get("sync_timeout", 30),
            max_concurrent_tasks=data.get("max_concurrent_tasks", 10),
            db_path=data.get("db_path", "nmap_tasks.db"),
            nmap_path=data.get("nmap_path", "nmap"),
        )

        # 如果 Token 为空，自动生成
        if not config.token:
            config.token = generate_token()
            print(f"[警告] 配置文件中未设置 token，已自动生成: {config.token}")

        return config

    @classmethod
    def load(cls, config_path: str | Path = None) -> "Config":
        """
        加载配置
        优先级：指定路径 > 默认路径 > 默认值
        """
        # 如果指定了路径，使用指定路径
        if config_path:
            return cls.from_json_file(config_path)

        # 否则尝试默认路径
        if DEFAULT_CONFIG_PATH.exists():
            print(f"[信息] 加载配置文件: {DEFAULT_CONFIG_PATH}")
            return cls.from_json_file(DEFAULT_CONFIG_PATH)

        # 都没有则使用默认值
        print(f"[警告] 未找到配置文件，使用默认配置")
        config = cls()
        config.token = generate_token()
        return config

    def to_dict(self) -> dict:
        """转换为字典"""
        return asdict(self)

    def save_to_file(self, file_path: str | Path):
        """保存配置到文件"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    def get_base_url(self) -> str:
        """获取服务器基础 URL"""
        return f"http://{self.host}:{self.port}{self.path}"

    def get_mcp_config(self) -> dict:
        """生成 MCP 客户端配置（URL Token 方式）"""
        base_url = self.get_base_url()
        return {
            "mcpServers": {
                "nmap-scanner": {
                    "name": "Nmap Scanner",
                    "type": "streamableHttp",
                    "description": "Nmap 端口扫描服务，支持快速扫描、全量扫描和自定义扫描",
                    "isActive": True,
                    "baseUrl": f"{base_url}?token={self.token}"
                }
            }
        }

    def get_mcp_config_bearer(self) -> dict:
        """生成 MCP 客户端配置（Bearer Token 方式）"""
        return {
            "mcpServers": {
                "nmap-scanner": {
                    "name": "Nmap Scanner",
                    "type": "streamableHttp",
                    "description": "Nmap 端口扫描服务，支持快速扫描、全量扫描和自定义扫描",
                    "isActive": True,
                    "baseUrl": self.get_base_url(),
                    "headers": {
                        "Authorization": f"Bearer {self.token}"
                    }
                }
            }
        }


def create_example_config():
    """生成示例配置文件"""
    example_config = {
        "host": "0.0.0.0",
        "port": 3004,
        "path": "/mcp",
        "token": "your_secret_token_here",
        "sync_timeout": 30,
        "max_concurrent_tasks": 10,
        "db_path": "nmap_tasks.db",
        "nmap_path": "nmap"
    }

    with open(EXAMPLE_CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(example_config, f, indent=2, ensure_ascii=False)

    print(f"[信息] 已生成示例配置文件: {EXAMPLE_CONFIG_PATH}")


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="Nmap MCP Server - 基于 HTTP 的 Nmap 扫描服务",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用默认配置文件 (config.json)
  python server.py

  # 指定配置文件路径
  python server.py -c /path/to/config.json
  python server.py --config /path/to/config.json

  # 生成示例配置文件
  python server.py --init
        """
    )

    parser.add_argument(
        '-c', '--config',
        type=str,
        default=None,
        help='配置文件路径 (默认: ./config.json)'
    )

    parser.add_argument(
        '--init',
        action='store_true',
        help='生成示例配置文件 config.example.json'
    )

    return parser.parse_args()


# 解析命令行参数
args = parse_args()

# 如果是初始化模式，生成示例配置后退出
if args.init:
    create_example_config()
    exit(0)

# 加载配置
config = Config.load(args.config)
