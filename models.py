"""
Nmap MCP Server 数据模型
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import json


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskType(str, Enum):
    """任务类型"""
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


@dataclass
class PortInfo:
    """端口信息"""
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""

    def to_dict(self) -> dict:
        result = {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
        }
        if self.version:
            result["version"] = self.version
        return result


@dataclass
class HostInfo:
    """主机信息"""
    address: str
    status: str
    hostname: str = ""
    ports: list[PortInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "status": self.status,
            "hostname": self.hostname,
            "ports": [p.to_dict() for p in self.ports],
        }


@dataclass
class ScanResult:
    """扫描结果"""
    target: str
    scan_time: str
    hosts: list[HostInfo] = field(default_factory=list)
    raw_output: str = ""
    command: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "command": self.command,
            "hosts": [h.to_dict() for h in self.hosts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


@dataclass
class ScanTask:
    """扫描任务"""
    id: str
    task_type: TaskType
    target: str
    command: str
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[str] = None  # JSON 格式的结果
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_type": self.task_type.value,
            "target": self.target,
            "command": self.command,
            "status": self.status.value,
            "result": json.loads(self.result) if self.result else None,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def to_status_dict(self) -> dict:
        """只返回状态信息，不包含完整结果"""
        return {
            "id": self.id,
            "task_type": self.task_type.value,
            "target": self.target,
            "status": self.status.value,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
