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
基于 HTTP 的 Nmap 网络端口扫描服务。

工具列表：
- quick_scan: 快速扫描常用端口
- full_scan: 全端口扫描（1-65535）
- custom_scan: 自定义 Nmap 命令
- get_task_status: 查询任务状态
- get_task_result: 获取任务结果

扫描完成前超时会返回任务 ID 供后续查询。服务器最多支持 10 个并发任务。
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
        description="扫描目标，支持 IP、域名或 CIDR 格式"
    )],
    timeout: Annotated[Optional[int], Field(
        default=None,
        description="同步等待超时（秒），默认 30 秒，范围 5-300。超时后返回任务 ID 供后续异步查询",
        ge=5,
        le=300
    )] = None,
) -> dict:
    """快速扫描常用端口（约 100 个），返回结构化的主机和端口信息。"""
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
        description="扫描目标，支持 IP、域名或 CIDR 格式"
    )],
    timeout: Annotated[Optional[int], Field(
        default=None,
        description="同步等待超时（秒），默认 30 秒，范围 5-600。全端口扫描耗时较长，建议设置更大的超时值",
        ge=5,
        le=600
    )] = None,
) -> dict:
    """全端口扫描（1-65535）并进行服务版本检测，返回详细的端口和服务信息。扫描通常需要数分钟。"""
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
        description="Nmap 命令参数和目标，支持所有 Nmap 参数。无需包含 'nmap' 命令本身"
    )],
    timeout: Annotated[Optional[int], Field(
        default=None,
        description="同步等待超时（秒），默认 30 秒，范围 5-600。根据扫描复杂度调整超时值",
        ge=5,
        le=600
    )] = None,
) -> dict:
    """执行自定义 Nmap 命令，返回原始输出文本。支持端口范围、扫描类型、脚本等所有 Nmap 参数。"""
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
        description="任务 ID（UUID 格式），由扫描工具返回"
    )]
) -> dict:
    """查询任务状态，返回任务基本信息、当前状态（pending/running/completed/failed）及时间戳。"""
    task = task_manager.get_task(task_id)

    if not task:
        return {
            "error": f"任务不存在: {task_id}",
        }

    return task.to_status_dict()


@mcp.tool
async def get_task_result(
    task_id: Annotated[str, Field(
        description="任务 ID（UUID 格式），由扫描工具返回"
    )]
) -> dict:
    """获取任务完整结果，包含扫描数据（结构化或原始输出）、命令、状态及时间戳。"""
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
