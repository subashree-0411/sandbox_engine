"""
AgentGuard-X — Sandbox Pool Manager
Person 3: Infrastructure + Sandbox Engineer

Manages a pre-warmed pool of gVisor containers.
Core principle: containers wait idle BEFORE requests arrive.
Every container is destroyed after ONE execution. No state persists.
"""

import asyncio
import docker
import threading
import time
import uuid
import logging
import json
from dataclasses import dataclass, field
from typing import Optional

# Structured logging — every event is a JSON line
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
)
log = logging.getLogger("sandbox.pool")


@dataclass
class SandboxContainer:
    """Represents one pre-warmed container in the pool."""
    container_id: str
    container_obj: object          # docker container object
    runtime: str                   # "runsc" (gVisor) or "runc" (Docker)
    created_at: float = field(default_factory=time.time)
    last_health_check: float = field(default_factory=time.time)

    @property
    def age_seconds(self):
        return time.time() - self.created_at

    def is_healthy(self):
        """Check the container is still alive and responsive."""
        try:
            self.container_obj.reload()
            return self.container_obj.status == "running"
        except Exception:
            return False


class SandboxPool:
    """
    Pre-warmed pool of gVisor sandbox containers.

    Architecture:
    - N containers boot at startup and sit idle
    - When a request arrives: checkout (< 15ms) → execute → destroy
    - A replacement container is pre-warmed in background immediately after checkout
    - Health monitor runs every 30s — replaces dead idle containers
    - Pool autoscales: if available < min_threshold, add more
    """

    # How old a container is allowed to get before we replace it proactively
    MAX_CONTAINER_AGE_SECONDS = 300   # 5 minutes

    def __init__(
        self,
        pool_size: int = 3,
        image: str = "python:3.10-slim",
        runtime: str = "runsc",       # "runsc" = gVisor, "runc" = plain Docker
        min_available: int = 1,       # autoscale if available drops below this
    ):
        self.pool_size = pool_size
        self.image = image
        self.runtime = runtime
        self.min_available = min_available

        self.client = docker.from_env()
        self._pool: list[SandboxContainer] = []
        self._lock = threading.Lock()
        self._running = False
        self._health_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self):
        """Boot the pool. Call once at service startup."""
        log.info(f"Pool starting — target size={self.pool_size}, runtime={self.runtime}")
        self._running = True

        for i in range(self.pool_size):
            sb = self._create_container()
            if sb:
                with self._lock:
                    self._pool.append(sb)
                log.info(f"Container ready [{i+1}/{self.pool_size}]: {sb.container_id}")

        log.info(f"Pool ready — {len(self._pool)} sandboxes available")

        # Start background health monitor
        self._health_thread = threading.Thread(
            target=self._health_monitor, daemon=True
        )
        self._health_thread.start()

    def stop(self):
        """Cleanly destroy all idle containers and shut down."""
        self._running = False
        with self._lock:
            for sb in self._pool:
                self._destroy_container(sb)
            self._pool.clear()
        log.info("Pool shut down. All containers destroyed.")

    # ------------------------------------------------------------------ #
    # Core operations
    # ------------------------------------------------------------------ #

    def checkout(self) -> Optional[SandboxContainer]:
        """
        Grab one idle container from the pool.
        Returns immediately — this is why pre-warming matters.
        Triggers background replenishment automatically.
        """
        with self._lock:
            if not self._pool:
                log.warning("Pool empty — creating emergency container (cold start)")
                sb = self._create_container()
                return sb

            sb = self._pool.pop(0)
            remaining = len(self._pool)

        log.info(f"Checked out {sb.container_id} — {remaining} remaining in pool")

        # Immediately start replenishing so pool never runs dry
        t = threading.Thread(target=self._replenish, daemon=True)
        t.start()

        # Autoscale: if we're running low, add extra
        if remaining < self.min_available:
            t2 = threading.Thread(target=self._replenish, daemon=True)
            t2.start()

        return sb

    def execute(self, sb: SandboxContainer, command: str) -> dict:
        """
        Run a command inside the sandbox container.
        Returns raw execution result — behavioral engine scores this.
        """
        log.info(f"Executing in {sb.container_id}: {command[:80]}")

        start = time.time()
        try:
            result = sb.container_obj.exec_run(
                cmd=["sh", "-c", command],
                stdout=True,
                stderr=True,
                demux=False
            )
            elapsed = time.time() - start
            output = result.output.decode("utf-8", errors="replace") if result.output else ""

            return {
                "exit_code": result.exit_code,
                "output": output[:500],          # cap output for safety
                "execution_time_seconds": round(elapsed, 3),
                "container_id": sb.container_id,
                "runtime": sb.runtime,
            }

        except Exception as e:
            elapsed = time.time() - start
            log.error(f"Execution error in {sb.container_id}: {e}")
            return {
                "exit_code": -1,
                "output": str(e),
                "execution_time_seconds": round(elapsed, 3),
                "container_id": sb.container_id,
                "runtime": sb.runtime,
                "error": str(e),
            }

    def destroy(self, sb: SandboxContainer):
        """
        Destroy a container after use.
        Called ALWAYS — whether execution succeeded or failed.
        State cannot persist between executions.
        """
        self._destroy_container(sb)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _create_container(self) -> Optional[SandboxContainer]:
        """Create and start one idle sandbox container."""
        try:
            container = self.client.containers.run(
                self.image,
                command="sleep infinity",
                runtime=self.runtime,
                detach=True,
                remove=False,
                network_mode="none",       # NO network inside sandbox
                read_only=False,
                mem_limit="128m",
                cpu_quota=50000,           # 50% of one core
                name=f"agx-{self.runtime}-{uuid.uuid4().hex[:8]}",
            )
            return SandboxContainer(
                container_id=container.short_id,
                container_obj=container,
                runtime=self.runtime,
            )
        except Exception as e:
            log.error(f"Failed to create container: {e}")
            return None

    def _destroy_container(self, sb: SandboxContainer):
        """Kill and remove one container. Always succeeds silently."""
        try:
            sb.container_obj.kill()
            sb.container_obj.remove(force=True)
            log.info(f"Destroyed {sb.container_id} — state wiped")
        except Exception:
            pass   # container may already be gone

    def _replenish(self):
        """Create a fresh container and add it to the pool."""
        sb = self._create_container()
        if sb:
            with self._lock:
                self._pool.append(sb)
            log.info(f"Pool replenished — new container: {sb.container_id}")

    def _health_monitor(self):
        """
        Background thread — runs every 30 seconds.
        Replaces dead or stale idle containers before they're ever checked out.
        This is what makes the pool reliable under long-running operation.
        """
        while self._running:
            time.sleep(30)
            dead = []
            stale = []

            with self._lock:
                for sb in self._pool:
                    if not sb.is_healthy():
                        dead.append(sb)
                    elif sb.age_seconds > self.MAX_CONTAINER_AGE_SECONDS:
                        stale.append(sb)

                for sb in dead + stale:
                    self._pool.remove(sb)

            for sb in dead:
                log.warning(f"Health check: container {sb.container_id} dead — removing")
                self._destroy_container(sb)

            for sb in stale:
                log.info(f"Health check: container {sb.container_id} stale ({sb.age_seconds:.0f}s) — rotating")
                self._destroy_container(sb)

            # Refill to target size
            with self._lock:
                deficit = self.pool_size - len(self._pool)

            for _ in range(deficit):
                self._replenish()

    @property
    def status(self) -> dict:
        """Current pool status — exposed via health endpoint."""
        with self._lock:
            return {
                "available": len(self._pool),
                "target_size": self.pool_size,
                "runtime": self.runtime,
                "min_available": self.min_available,
                "container_ids": [sb.container_id for sb in self._pool],
            }
