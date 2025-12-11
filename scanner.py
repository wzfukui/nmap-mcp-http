"""
Nmap 扫描器模块
"""
import asyncio
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional
import shlex

from config import config
from models import ScanResult, HostInfo, PortInfo, TaskType


class NmapScanner:
    """Nmap 扫描器"""

    def __init__(self, nmap_path: str = None):
        self.nmap_path = nmap_path or config.nmap_path

    def build_quick_scan_command(self, target: str) -> list[str]:
        """构建快速扫描命令"""
        return [
            self.nmap_path,
            "-F",  # 快速扫描（常用端口）
            "-T4",  # 较快的扫描速度
            "-oX", "-",  # XML 输出到 stdout
            target
        ]

    def build_full_scan_command(self, target: str) -> list[str]:
        """构建全量扫描命令"""
        return [
            self.nmap_path,
            "-p", "1-65535",  # 所有端口
            "-T4",  # 较快的扫描速度
            "-sV",  # 服务版本检测
            "-oX", "-",  # XML 输出到 stdout
            target
        ]

    def build_custom_scan_command(self, command: str) -> list[str]:
        """构建自定义扫描命令"""
        # 解析用户提供的命令
        parts = shlex.split(command)

        # 如果用户没有指定 nmap，添加它
        if parts and parts[0] != "nmap" and parts[0] != self.nmap_path:
            parts.insert(0, self.nmap_path)
        elif parts and parts[0] == "nmap":
            parts[0] = self.nmap_path

        return parts

    async def run_scan(
        self,
        command: list[str],
        task_type: TaskType,
    ) -> ScanResult:
        """执行扫描"""
        try:
            # 使用 asyncio 运行子进程
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='replace')
                raise RuntimeError(f"Nmap 执行失败: {error_msg}")

            output = stdout.decode('utf-8', errors='replace')

            # 根据任务类型决定是否解析 XML
            if task_type in (TaskType.QUICK, TaskType.FULL):
                # 尝试解析 XML 输出
                return self._parse_xml_output(output, command)
            else:
                # 自定义命令，返回原始输出
                return self._create_raw_result(output, command)

        except Exception as e:
            raise RuntimeError(f"扫描执行错误: {str(e)}")

    def _parse_xml_output(self, xml_output: str, command: list[str]) -> ScanResult:
        """解析 Nmap XML 输出"""
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            # XML 解析失败，返回原始输出
            return self._create_raw_result(xml_output, command)

        # 获取扫描信息
        runstats = root.find('runstats')
        scan_time = "unknown"
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                elapsed = finished.get('elapsed', 'unknown')
                scan_time = f"{elapsed}s"

        # 获取目标
        args = root.get('args', '')
        target = args.split()[-1] if args else 'unknown'

        # 解析主机信息
        hosts = []
        for host_elem in root.findall('host'):
            host_info = self._parse_host(host_elem)
            if host_info:
                hosts.append(host_info)

        return ScanResult(
            target=target,
            scan_time=scan_time,
            hosts=hosts,
            raw_output=xml_output,
            command=' '.join(command),
        )

    def _parse_host(self, host_elem: ET.Element) -> Optional[HostInfo]:
        """解析单个主机信息"""
        # 获取状态
        status_elem = host_elem.find('status')
        status = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'

        # 获取地址
        address = "unknown"
        for addr_elem in host_elem.findall('address'):
            if addr_elem.get('addrtype') == 'ipv4':
                address = addr_elem.get('addr', 'unknown')
                break
            elif addr_elem.get('addrtype') == 'ipv6':
                address = addr_elem.get('addr', 'unknown')

        # 获取主机名
        hostname = ""
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', '')

        # 解析端口信息
        ports = []
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port_info = self._parse_port(port_elem)
                if port_info:
                    ports.append(port_info)

        return HostInfo(
            address=address,
            status=status,
            hostname=hostname,
            ports=ports,
        )

    def _parse_port(self, port_elem: ET.Element) -> Optional[PortInfo]:
        """解析端口信息"""
        port_id = int(port_elem.get('portid', 0))
        protocol = port_elem.get('protocol', 'tcp')

        # 获取状态
        state_elem = port_elem.find('state')
        state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

        # 获取服务信息
        service_elem = port_elem.find('service')
        service = ""
        version = ""
        if service_elem is not None:
            service = service_elem.get('name', '')
            product = service_elem.get('product', '')
            ver = service_elem.get('version', '')
            if product or ver:
                version = f"{product} {ver}".strip()

        return PortInfo(
            port=port_id,
            protocol=protocol,
            state=state,
            service=service,
            version=version,
        )

    def _create_raw_result(self, output: str, command: list[str]) -> ScanResult:
        """创建原始输出结果"""
        # 尝试从命令中提取目标
        target = command[-1] if command else "unknown"

        return ScanResult(
            target=target,
            scan_time="unknown",
            hosts=[],
            raw_output=output,
            command=' '.join(command),
        )


# 全局扫描器实例
scanner = NmapScanner()
