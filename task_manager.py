"""
Nmap MCP Server 任务管理器
"""
import sqlite3
import threading
import uuid
from datetime import datetime
from typing import Optional
from contextlib import contextmanager

from config import config
from models import ScanTask, TaskStatus, TaskType


class TaskManager:
    """任务管理器 - 管理扫描任务的生命周期"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """获取线程本地的数据库连接"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    @contextmanager
    def _get_cursor(self):
        """获取数据库游标的上下文管理器"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    def _init_db(self):
        """初始化数据库表"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_tasks (
                    id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    result TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                )
            """)
            # 创建索引以加速查询
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_status ON scan_tasks(status)
            """)

    def create_task(self, task_type: TaskType, target: str, command: str) -> ScanTask:
        """创建新任务"""
        task_id = str(uuid.uuid4())
        now = datetime.now()

        task = ScanTask(
            id=task_id,
            task_type=task_type,
            target=target,
            command=command,
            status=TaskStatus.PENDING,
            created_at=now,
        )

        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO scan_tasks (id, task_type, target, command, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                task.id,
                task.task_type.value,
                task.target,
                task.command,
                task.status.value,
                task.created_at.isoformat(),
            ))

        return task

    def get_task(self, task_id: str) -> Optional[ScanTask]:
        """获取任务"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM scan_tasks WHERE id = ?
            """, (task_id,))
            row = cursor.fetchone()

        if not row:
            return None

        return self._row_to_task(row)

    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        result: str = None,
        error_message: str = None,
    ):
        """更新任务状态"""
        now = datetime.now()

        with self._get_cursor() as cursor:
            if status == TaskStatus.RUNNING:
                cursor.execute("""
                    UPDATE scan_tasks
                    SET status = ?, started_at = ?
                    WHERE id = ?
                """, (status.value, now.isoformat(), task_id))
            elif status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                cursor.execute("""
                    UPDATE scan_tasks
                    SET status = ?, result = ?, error_message = ?, completed_at = ?
                    WHERE id = ?
                """, (status.value, result, error_message, now.isoformat(), task_id))
            else:
                cursor.execute("""
                    UPDATE scan_tasks
                    SET status = ?
                    WHERE id = ?
                """, (status.value, task_id))

    def get_running_task_count(self) -> int:
        """获取正在运行的任务数量"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) FROM scan_tasks WHERE status = ?
            """, (TaskStatus.RUNNING.value,))
            row = cursor.fetchone()
            return row[0] if row else 0

    def can_accept_task(self) -> bool:
        """检查是否可以接受新任务"""
        return self.get_running_task_count() < config.max_concurrent_tasks

    def get_pending_tasks(self) -> list[ScanTask]:
        """获取所有待执行的任务"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM scan_tasks WHERE status = ?
                ORDER BY created_at ASC
            """, (TaskStatus.PENDING.value,))
            rows = cursor.fetchall()

        return [self._row_to_task(row) for row in rows]

    def _row_to_task(self, row: sqlite3.Row) -> ScanTask:
        """将数据库行转换为任务对象"""
        return ScanTask(
            id=row['id'],
            task_type=TaskType(row['task_type']),
            target=row['target'],
            command=row['command'],
            status=TaskStatus(row['status']),
            result=row['result'],
            error_message=row['error_message'],
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
            started_at=datetime.fromisoformat(row['started_at']) if row['started_at'] else None,
            completed_at=datetime.fromisoformat(row['completed_at']) if row['completed_at'] else None,
        )


# 全局任务管理器实例
task_manager = TaskManager()
