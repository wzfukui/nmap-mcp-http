"""
Nmap MCP Server - 基于 Streamable HTTP 的远程 Nmap 扫描服务
"""
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Annotated

from fastmcp import FastMCP
from pydantic import Field
from starlette.middleware import Middleware

from config import config

# 读取版本号
VERSION_FILE = Path(__file__).parent / "VERSION"
__version__ = VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "unknown"
from models import TaskType, TaskStatus, ScanResult
from task_manager import task_manager
from scanner import scanner
from auth import TokenAuthMiddleware


# 创建 FastMCP 服务器
mcp = FastMCP(
    name="Nmap MCP Server",
    instructions="""
Nmap MCP Server 是一个基于 HTTP 的网络端口扫描服务。

## 可用工具

1. **quick_scan** - 快速扫描目标主机的常用端口（约100个），适合快速了解主机开放情况
2. **full_scan** - 全量扫描目标主机的所有端口（1-65535），适合深度安全评估
3. **custom_scan** - 执行自定义 Nmap 命令，支持所有 Nmap 参数
4. **get_task_status** - 查询扫描任务的当前状态
5. **get_task_result** - 获取扫描任务的完整结果

## 使用流程

1. 调用扫描工具（quick_scan/full_scan/custom_scan）
2. 如果扫描在超时时间内完成，直接返回结果
3. 如果扫描超时，返回任务 ID，后续通过 get_task_status/get_task_result 查询

## 注意事项

- 快速扫描通常几秒内完成
- 全量扫描可能需要数分钟
- 服务器最多支持 10 个并发扫描任务
""",
)

# 线程池用于执行阻塞操作
executor = ThreadPoolExecutor(max_workers=config.max_concurrent_tasks)


async def execute_scan_with_timeout(
    task_type: TaskType,
    target: str,
    command: list[str],
    timeout: int = None,
) -> tuple[bool, Optional[ScanResult], Optional[str]]:
    """
    执行扫描，带超时控制

    返回: (completed, result, task_id)
    - completed: 是否在超时前完成
    - result: 扫描结果（如果完成）
    - task_id: 任务 ID（如果超时）
    """
    timeout = timeout or config.sync_timeout

    # 检查并发限制
    if not task_manager.can_accept_task():
        raise RuntimeError(
            f"服务器繁忙，当前已有 {config.max_concurrent_tasks} 个任务在执行，请稍后重试"
        )

    # 创建任务记录
    task = task_manager.create_task(
        task_type=task_type,
        target=target,
        command=' '.join(command),
    )

    # 更新状态为运行中
    task_manager.update_task_status(task.id, TaskStatus.RUNNING)

    try:
        # 尝试在超时时间内完成扫描
        result = await asyncio.wait_for(
            scanner.run_scan(command, task_type),
            timeout=timeout - 2  # 留 2 秒余量
        )

        # 扫描成功，更新任务状态
        task_manager.update_task_status(
            task.id,
            TaskStatus.COMPLETED,
            result=result.to_json(),
        )

        return True, result, task.id

    except asyncio.TimeoutError:
        # 超时，任务继续在后台执行
        # 启动后台任务继续执行
        asyncio.create_task(
            _continue_scan_in_background(task.id, command, task_type)
        )
        return False, None, task.id

    except Exception as e:
        # 扫描失败
        task_manager.update_task_status(
            task.id,
            TaskStatus.FAILED,
            error_message=str(e),
        )
        raise


async def _continue_scan_in_background(
    task_id: str,
    command: list[str],
    task_type: TaskType,
):
    """在后台继续执行扫描"""
    try:
        result = await scanner.run_scan(command, task_type)
        task_manager.update_task_status(
            task_id,
            TaskStatus.COMPLETED,
            result=result.to_json(),
        )
    except Exception as e:
        task_manager.update_task_status(
            task_id,
            TaskStatus.FAILED,
            error_message=str(e),
        )


@mcp.tool
async def quick_scan(
    target: Annotated[str, Field(
        description="目标 IP 地址或主机名，支持单个 IP（如 192.168.1.1）、域名（如 example.com）或 CIDR 格式（如 192.168.1.0/24）",
        examples=["192.168.1.1", "example.com", "10.0.0.1"]
    )],
    timeout: Annotated[Optional[int], Field(
        default=None,
        description="同步等待超时时间（秒）。如果扫描在此时间内完成则直接返回结果，否则返回任务 ID 供后续查询。默认 30 秒",
        ge=5,
        le=300,
        examples=[30, 60]
    )] = None,
) -> dict:
    """快速扫描目标主机的常用端口。

    使用 Nmap 的 -F（快速模式）扫描约 100 个最常用的端口，适合快速了解目标主机的端口开放情况。
    扫描结果以结构化 JSON 格式返回，包含主机状态、开放端口列表及对应服务信息。

    返回结果包含:
    - status: 扫描状态（completed 或 pending）
    - task_id: 任务 ID，用于后续查询
    - result: 扫描结果（仅当 status 为 completed 时）
      - target: 扫描目标
      - scan_time: 扫描耗时
      - hosts: 主机列表，每个主机包含地址、状态、开放端口等信息
    """
    command = scanner.build_quick_scan_command(target)

    completed, result, task_id = await execute_scan_with_timeout(
        task_type=TaskType.QUICK,
        target=target,
        command=command,
        timeout=timeout,
    )

    if completed:
        return {
            "status": "completed",
            "task_id": task_id,
            "result": result.to_dict(),
        }
    else:
        return {
            "status": "pending",
            "task_id": task_id,
            "message": "扫描任务已提交，请使用 get_task_status 或 get_task_result 查询结果",
        }


@mcp.tool
async def full_scan(
    target: Annotated[str, Field(
        description="目标 IP 地址或主机名，支持单个 IP（如 192.168.1.1）、域名（如 example.com）或 CIDR 格式（如 192.168.1.0/24）",
        examples=["192.168.1.1", "example.com", "10.0.0.1"]
    )],
    timeout: Annotated[Optional[int], Field(
        default=None,
        description="同步等待超时时间（秒）。全量扫描通常需要较长时间，建议设置较大的超时值或使用默认值后通过任务 ID 查询结果。默认 30 秒",
        ge=5,
        le=600,
        examples=[60, 120, 300]
    )] = None,
) -> dict:
    """全量扫描目标主机的所有端口（1-65535）。

    扫描目标主机的全部 65535 个端口，并进行服务版本检测（-sV）。
    适合进行深度安全评估，但扫描时间较长（通常需要数分钟）。

    返回结果包含:
    - status: 扫描状态（completed 或 pending）
    - task_id: 任务 ID，用于后续查询
    - result: 扫描结果（仅当 status 为 completed 时）
      - target: 扫描目标
      - scan_time: 扫描耗时
      - hosts: 主机列表，包含详细的端口和服务版本信息
    """
    command = scanner.build_full_scan_command(target)

    completed, result, task_id = await execute_scan_with_timeout(
        task_type=TaskType.FULL,
        target=target,
        command=command,
        timeout=timeout,
    )

    if completed:
        return {
            "status": "completed",
            "task_id": task_id,
            "result": result.to_dict(),
        }
    else:
        return {
            "status": "pending",
            "task_id": task_id,
            "message": "扫描任务已提交，请使用 get_task_status 或 get_task_result 查询结果",
        }


@mcp.tool
async def custom_scan(
    command: Annotated[str, Field(
        description="Nmap 命令参数和目标。可以包含任意 Nmap 支持的参数，如端口范围、扫描类型、脚本等。不需要包含 'nmap' 命令本身",
        examples=[
            "-sS -p 80,443,8080 192.168.1.1",
            "-sV -sC -p 22 example.com",
            "-sn 192.168.1.0/24",
            "-A -T4 10.0.0.1",
            "--script vuln 192.168.1.1"
        ]
    )],
    timeout: Annotated[Optional[int], Field(
        default=None,
        description="同步等待超时时间（秒）。根据扫描复杂度设置合适的超时值。默认 30 秒",
        ge=5,
        le=600,
        examples=[30, 60, 120]
    )] = None,
) -> dict:
    """执行自定义 Nmap 扫描命令。

    支持所有 Nmap 命令行参数，可实现各种高级扫描需求，如：
    - 指定端口范围: -p 1-1000
    - SYN 扫描: -sS
    - 服务版本检测: -sV
    - 操作系统检测: -O
    - 脚本扫描: --script <script-name>
    - 主机发现: -sn
    - 激进扫描: -A

    返回结果包含:
    - status: 扫描状态（completed 或 pending）
    - task_id: 任务 ID，用于后续查询
    - result: 扫描结果（仅当 status 为 completed 时）
      - target: 扫描目标
      - command: 实际执行的完整命令
      - raw_output: Nmap 原始输出文本
    """
    cmd_parts = scanner.build_custom_scan_command(command)

    # 从命令中提取目标（通常是最后一个参数）
    target = cmd_parts[-1] if cmd_parts else "unknown"

    completed, result, task_id = await execute_scan_with_timeout(
        task_type=TaskType.CUSTOM,
        target=target,
        command=cmd_parts,
        timeout=timeout,
    )

    if completed:
        # 自定义扫描返回原始输出
        return {
            "status": "completed",
            "task_id": task_id,
            "result": {
                "target": result.target,
                "command": result.command,
                "raw_output": result.raw_output,
            },
        }
    else:
        return {
            "status": "pending",
            "task_id": task_id,
            "message": "扫描任务已提交，请使用 get_task_status 或 get_task_result 查询结果",
        }


@mcp.tool
async def get_task_status(
    task_id: Annotated[str, Field(
        description="扫描任务的唯一标识符（UUID 格式），由扫描工具返回",
        examples=["550e8400-e29b-41d4-a716-446655440000"]
    )]
) -> dict:
    """查询扫描任务的当前状态。

    用于检查异步扫描任务的执行进度，返回任务的基本信息和当前状态。

    返回结果包含:
    - id: 任务 ID
    - task_type: 任务类型（quick/full/custom）
    - target: 扫描目标
    - status: 当前状态
      - pending: 等待执行
      - running: 正在扫描
      - completed: 扫描完成
      - failed: 扫描失败
    - created_at: 任务创建时间
    - started_at: 开始执行时间
    - completed_at: 完成时间
    - error_message: 错误信息（仅当 status 为 failed 时）
    """
    task = task_manager.get_task(task_id)

    if not task:
        return {
            "error": f"任务不存在: {task_id}",
        }

    return task.to_status_dict()


@mcp.tool
async def get_task_result(
    task_id: Annotated[str, Field(
        description="扫描任务的唯一标识符（UUID 格式），由扫描工具返回",
        examples=["550e8400-e29b-41d4-a716-446655440000"]
    )]
) -> dict:
    """获取扫描任务的完整结果。

    用于获取已完成扫描任务的详细结果，包括所有扫描数据。

    返回结果包含:
    - id: 任务 ID
    - task_type: 任务类型（quick/full/custom）
    - target: 扫描目标
    - command: 执行的 Nmap 命令
    - status: 当前状态
    - result: 扫描结果（仅当 status 为 completed 时）
      - 对于 quick_scan/full_scan: 结构化的主机和端口信息
      - 对于 custom_scan: 原始输出文本
    - created_at: 任务创建时间
    - started_at: 开始执行时间
    - completed_at: 完成时间
    - error_message: 错误信息（仅当 status 为 failed 时）
    """
    task = task_manager.get_task(task_id)

    if not task:
        return {
            "error": f"任务不存在: {task_id}",
        }

    return task.to_dict()


def print_startup_info():
    """打印启动信息和 MCP 配置"""
    print("\n" + "=" * 70)
    print(f"Nmap MCP Server v{__version__}")
    print("https://github.com/flagify-com/nmap-mcp-http")
    print("=" * 70)
    print(f"  Host:              {config.host}")
    print(f"  Port:              {config.port}")
    print(f"  Path:              {config.path}")
    print(f"  Sync Timeout:      {config.sync_timeout}s")
    print(f"  Max Concurrent:    {config.max_concurrent_tasks}")
    print(f"  Database:          {config.db_path}")
    print(f"  Token:             {config.token}")
    print("=" * 70)
    print("\n鉴权方式 (二选一):")
    print("  1. URL 参数:        ?token=<your_token>")
    print("  2. HTTP Header:     Authorization: Bearer <your_token>")
    print("=" * 70)
    print("\nMCP Client 配置 - 方式1: URL Token (复制以下 JSON):")
    print("-" * 70)
    print(json.dumps(config.get_mcp_config(), indent=2, ensure_ascii=False))
    print("-" * 70)
    print("\nMCP Client 配置 - 方式2: Bearer Token (复制以下 JSON):")
    print("-" * 70)
    print(json.dumps(config.get_mcp_config_bearer(), indent=2, ensure_ascii=False))
    print("-" * 70)
    print("\n")


def main():
    """启动服务器"""
    # 创建带鉴权的中间件
    middleware = [
        Middleware(TokenAuthMiddleware, token=config.token)
    ]

    # 创建 HTTP 应用
    app = mcp.http_app(path=config.path, middleware=middleware)

    # 打印启动信息
    print_startup_info()

    # 启动服务
    import uvicorn
    import sys
    import warnings
    # 忽略 websockets 库的 deprecation 警告（uvicorn 内部加载，不影响 HTTP 功能）
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    # 强制刷新 stdout 以确保启动信息先输出
    sys.stdout.flush()
    uvicorn.run(app, host=config.host, port=config.port, log_level="warning")


if __name__ == "__main__":
    main()
