"""
Nmap MCP Server 测试客户端
"""
import asyncio
import json
import sys
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


def parse_tool_result(result):
    """解析工具调用结果"""
    if result is None:
        return None

    # FastMCP 返回 CallToolResult 对象
    if hasattr(result, 'content'):
        content_list = result.content
        if content_list and len(content_list) > 0:
            content = content_list[0]
            if hasattr(content, 'text'):
                return json.loads(content.text)

    # 如果是列表
    if isinstance(result, list) and len(result) > 0:
        content = result[0]
        if hasattr(content, 'text'):
            return json.loads(content.text)

    return None


async def test_quick_scan(client: Client, target: str = "127.0.0.1"):
    """测试快速扫描"""
    print("\n" + "=" * 60)
    print(f"测试 quick_scan - 目标: {target}")
    print("=" * 60)

    result = await client.call_tool("quick_scan", {"target": target, "timeout": 60})
    data = parse_tool_result(result)
    print(f"结果:\n{json.dumps(data, indent=2, ensure_ascii=False)}")
    return data


async def test_get_task_status(client: Client, task_id: str):
    """测试查询任务状态"""
    print("\n" + "=" * 60)
    print(f"测试 get_task_status - 任务ID: {task_id}")
    print("=" * 60)

    result = await client.call_tool("get_task_status", {"task_id": task_id})
    data = parse_tool_result(result)
    print(f"结果:\n{json.dumps(data, indent=2, ensure_ascii=False)}")
    return data


async def test_get_task_result(client: Client, task_id: str):
    """测试获取任务结果"""
    print("\n" + "=" * 60)
    print(f"测试 get_task_result - 任务ID: {task_id}")
    print("=" * 60)

    result = await client.call_tool("get_task_result", {"task_id": task_id})
    data = parse_tool_result(result)
    print(f"结果:\n{json.dumps(data, indent=2, ensure_ascii=False)}")
    return data


async def test_custom_scan(client: Client, command: str):
    """测试自定义扫描"""
    print("\n" + "=" * 60)
    print(f"测试 custom_scan - 命令: {command}")
    print("=" * 60)

    result = await client.call_tool("custom_scan", {"command": command, "timeout": 60})
    data = parse_tool_result(result)
    print(f"结果:\n{json.dumps(data, indent=2, ensure_ascii=False)}")
    return data


async def list_tools(client: Client):
    """列出所有可用工具"""
    print("\n" + "=" * 60)
    print("可用工具列表")
    print("=" * 60)

    tools = await client.list_tools()
    for tool in tools:
        print(f"\n工具名称: {tool.name}")
        print(f"描述: {tool.description[:100]}..." if len(tool.description) > 100 else f"描述: {tool.description}")


async def test_with_url_token(server_url: str):
    """测试 URL Token 鉴权"""
    print("\n" + "#" * 70)
    print("测试方式 1: URL Token 鉴权")
    print("#" * 70)

    async with Client(server_url) as client:
        await list_tools(client)
        result = await test_quick_scan(client, "127.0.0.1")
        if result and result.get("task_id"):
            await test_get_task_status(client, result["task_id"])


async def test_with_header_token(base_url: str, token: str):
    """测试 Header Bearer Token 鉴权"""
    print("\n" + "#" * 70)
    print("测试方式 2: HTTP Header Bearer Token 鉴权")
    print("#" * 70)

    transport = StreamableHttpTransport(
        url=base_url,
        headers={"Authorization": f"Bearer {token}"}
    )

    async with Client(transport) as client:
        await list_tools(client)
        result = await test_quick_scan(client, "127.0.0.1")
        if result and result.get("task_id"):
            await test_get_task_status(client, result["task_id"])


async def test_without_token(base_url: str):
    """测试无 Token 请求（应该被拒绝）"""
    print("\n" + "#" * 70)
    print("测试方式 3: 无 Token 请求（应该被拒绝）")
    print("#" * 70)

    try:
        async with Client(base_url) as client:
            await list_tools(client)
            print("错误：无 Token 请求不应该成功！")
    except Exception as e:
        print(f"预期的错误（鉴权失败）: {type(e).__name__}: {e}")


async def test_with_wrong_token(base_url: str):
    """测试错误 Token 请求（应该被拒绝）"""
    print("\n" + "#" * 70)
    print("测试方式 4: 错误 Token 请求（应该被拒绝）")
    print("#" * 70)

    wrong_url = f"{base_url}?token=wrong_token_12345"
    try:
        async with Client(wrong_url) as client:
            await list_tools(client)
            print("错误：错误 Token 请求不应该成功！")
    except Exception as e:
        print(f"预期的错误（鉴权失败）: {type(e).__name__}: {e}")


async def main():
    """主测试函数"""
    # 从命令行参数获取 Token，或使用默认值
    if len(sys.argv) < 2:
        print("用法: python test_client.py <token>")
        print("示例: python test_client.py abc123xyz")
        sys.exit(1)

    token = sys.argv[1]
    base_url = "http://127.0.0.1:3004/mcp"
    url_with_token = f"{base_url}?token={token}"

    print(f"服务器地址: {base_url}")
    print(f"Token: {token}")

    # 测试 1: URL Token 鉴权
    await test_with_url_token(url_with_token)

    # 测试 2: Header Token 鉴权
    await test_with_header_token(base_url, token)

    # 测试 3: 无 Token 请求
    await test_without_token(base_url)

    # 测试 4: 错误 Token 请求
    await test_with_wrong_token(base_url)

    print("\n" + "=" * 70)
    print("所有测试完成!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
