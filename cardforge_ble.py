#!/usr/bin/env python3
"""
CardForge BLE - firmware de vinculação da máquina (Raspberry Pi 4B)

Python 3.11.10 | bless (servidor GATT sobre BlueZ) | NetworkManager (nmcli)

O Raspberry não precisa de rede: o app CardForge se comunica por Bluetooth
Low Energy para (1) autenticar com a senha da máquina e registrar o usuário
como permitido e (2) opcionalmente enviar o Wi-Fi para a máquina se conectar.
O protocolo está descrito em CONTRATO_BLE.md.

Comandos:
  python cardforge_ble.py run                 inicia o servidor BLE (padrão)
  python cardforge_ble.py check               valida a configuração (.env)
  python cardforge_ble.py hash-password       gera o hash de uma senha
  python cardforge_ble.py secure-env ARQUIVO  troca MACHINE_PASSWORD por hash

Opção global:
  --env ARQUIVO   arquivo de configuração. Padrão: $CARDFORGE_ENV,
                  /etc/cardforge/cardforge.env ou ./.env
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import signal
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

if sys.version_info < (3, 11):
    sys.exit("CardForge BLE requer Python 3.11 ou superior.")

# =============================================================================
# Constantes do protocolo (devem bater com CONTRATO_BLE.md)
# =============================================================================
PROTOCOL_VERSION = 1
FIRMWARE_VERSION = "1.0.0"

SERVICE_UUID = "a3c1f000-6d2e-4b8a-9c3f-2e7d5b1a9c40"
RX_UUID = "a3c1f001-6d2e-4b8a-9c3f-2e7d5b1a9c40"  # app -> máquina (write)
TX_UUID = "a3c1f002-6d2e-4b8a-9c3f-2e7d5b1a9c40"  # máquina -> app (notify/read)

MAX_MESSAGE_BYTES = 180      # limite de uma mensagem (exige MTU >= 185)
MAX_INCOMING_BYTES = 512     # acima disso a escrita é descartada
PLACEHOLDER_PASSWORD = "troque-esta-senha"
PBKDF2_ITERATIONS = 300_000
DEFAULT_ENV_PATHS = (Path("/etc/cardforge/cardforge.env"),
                     Path(__file__).resolve().parent / ".env")

USERNAME_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,64}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9-]{1,16}$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
HEX64_RE = re.compile(r"^[0-9A-Fa-f]{64}$")

log = logging.getLogger("cardforge")


class ConfigError(Exception):
    """Configuração inválida no .env."""


# =============================================================================
# Senha da máquina (PBKDF2-SHA256, comparação em tempo constante)
# =============================================================================
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256:{iterations}:{_b64e(salt)}:{_b64e(dk)}"


def parse_password_hash(stored: str) -> tuple[int, bytes, bytes]:
    algo, iterations, salt, dk = stored.split(":")
    if algo != "pbkdf2_sha256" or int(iterations) < 100_000:
        raise ValueError("formato de hash não suportado")
    return int(iterations), _b64d(salt), _b64d(dk)


def verify_password(password: str, stored: str) -> bool:
    try:
        iterations, salt, expected = parse_password_hash(stored)
    except (ValueError, TypeError):
        return False
    calc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(calc, expected)


def generate_password(length: int = 10) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# =============================================================================
# Configuração
# =============================================================================
@dataclass(frozen=True)
class Config:
    model: str
    serial: str
    password_hash: str
    wifi_interface: str
    wifi_connect_timeout: int
    auth_max_attempts: int
    auth_lockout_seconds: int
    session_ttl_seconds: int
    max_allowed_users: int
    data_dir: Path
    log_level: str

    @property
    def name(self) -> str:
        return f"{self.model}-{self.serial}"

    @classmethod
    def from_env(cls) -> "Config":
        def text(key: str, default: str = "") -> str:
            return os.getenv(key, default).strip()

        def integer(key: str, default: int, lo: int, hi: int) -> int:
            raw = text(key, str(default))
            try:
                value = int(raw)
            except ValueError:
                raise ConfigError(f"{key} deve ser um número inteiro (recebido: {raw!r})")
            if not lo <= value <= hi:
                raise ConfigError(f"{key} deve estar entre {lo} e {hi} (recebido: {value})")
            return value

        model = text("MACHINE_MODEL", "CardForge-M1")
        if not MODEL_RE.fullmatch(model):
            raise ConfigError("MACHINE_MODEL: use 1-16 letras, números ou '-'")
        serial = text("MACHINE_SERIAL")
        if not SERIAL_RE.fullmatch(serial):
            raise ConfigError("MACHINE_SERIAL é obrigatório: 1-8 letras ou números (ex.: 001)")

        pw_hash = text("MACHINE_PASSWORD_HASH")
        password = os.getenv("MACHINE_PASSWORD", "")
        if pw_hash:
            try:
                parse_password_hash(pw_hash)
            except (ValueError, TypeError):
                raise ConfigError("MACHINE_PASSWORD_HASH inválido. Gere com: hash-password")
        elif password:
            if password == PLACEHOLDER_PASSWORD or len(password) < 6:
                raise ConfigError("MACHINE_PASSWORD: troque o valor de exemplo (mínimo 6 caracteres)")
            log.warning("Senha em texto puro no .env. Proteja com: secure-env <arquivo>")
            pw_hash = hash_password(password)
        else:
            raise ConfigError("Defina MACHINE_PASSWORD ou MACHINE_PASSWORD_HASH")

        iface = text("WIFI_INTERFACE", "wlan0")
        if not IFACE_RE.fullmatch(iface):
            raise ConfigError("WIFI_INTERFACE inválida")

        data_dir = Path(text("DATA_DIR") or os.getenv("STATE_DIRECTORY", "") or "/var/lib/cardforge")
        level = text("LOG_LEVEL", "INFO").upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ConfigError("LOG_LEVEL deve ser DEBUG, INFO, WARNING ou ERROR")

        return cls(
            model=model,
            serial=serial,
            password_hash=pw_hash,
            wifi_interface=iface,
            wifi_connect_timeout=integer("WIFI_CONNECT_TIMEOUT", 20, 5, 120),
            auth_max_attempts=integer("AUTH_MAX_ATTEMPTS", 5, 1, 20),
            auth_lockout_seconds=integer("AUTH_LOCKOUT_SECONDS", 60, 5, 3600),
            session_ttl_seconds=integer("SESSION_TTL_SECONDS", 300, 30, 3600),
            max_allowed_users=integer("MAX_ALLOWED_USERS", 20, 1, 1000),
            data_dir=data_dir,
            log_level=level,
        )


# =============================================================================
# Usuários permitidos (JSON com gravação atômica e permissão 600)
# =============================================================================
class UsersFullError(Exception):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class UserStore:
    def __init__(self, path: Path, max_users: int) -> None:
        self.path = path
        self.max_users = max_users
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data.get("machine_id"), str) and isinstance(data.get("users"), dict):
                    return data
                raise ValueError("estrutura inválida")
            except (OSError, ValueError) as exc:
                backup = self.path.with_suffix(f".corrupt-{int(time.time())}")
                log.error("Arquivo %s inválido (%s). Backup em %s", self.path, exc, backup)
                self.path.replace(backup)
        data = {"machine_id": str(uuid.uuid4()), "users": {}}
        self._save(data)
        return data

    def _save(self, data: dict[str, Any]) -> None:
        atomic_write(self.path, json.dumps(data, indent=2, ensure_ascii=False))

    @property
    def machine_id(self) -> str:
        return self.data["machine_id"]

    def add_or_touch(self, username: str) -> bool:
        """Registra o usuário como permitido. Retorna True se for novo."""
        key = username.lower()
        users: dict[str, Any] = self.data["users"]
        now = _now_iso()
        is_new = key not in users
        if is_new:
            if len(users) >= self.max_users:
                raise UsersFullError()
            users[key] = {"username": username, "linked_at": now, "last_seen": now}
        else:
            users[key]["last_seen"] = now
        self._save(self.data)
        return is_new


# =============================================================================
# Proteção contra força bruta (bloqueio progressivo, global)
# =============================================================================
class AuthGuard:
    MAX_LOCK_SECONDS = 3600

    def __init__(self, max_attempts: int, lockout_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.fails = 0
        self.lockouts = 0
        self.locked_until = 0.0

    def retry_after(self) -> int:
        return max(0, math.ceil(self.locked_until - time.monotonic()))

    def register_failure(self) -> int:
        """Retorna as tentativas restantes (0 = bloqueou agora)."""
        self.fails += 1
        if self.fails >= self.max_attempts:
            self.fails = 0
            self.lockouts += 1
            duration = min(self.lockout_seconds * 2 ** (self.lockouts - 1), self.MAX_LOCK_SECONDS)
            self.locked_until = time.monotonic() + duration
            log.warning("Muitas senhas erradas: bloqueado por %ss", duration)
            return 0
        return self.max_attempts - self.fails

    def register_success(self) -> None:
        self.fails = 0
        self.lockouts = 0


# =============================================================================
# Wi-Fi (NetworkManager via nmcli, sem shell)
# =============================================================================
@dataclass
class WifiResult:
    ok: bool
    code: str            # WIFI_CONNECTED ou motivo da falha
    ssid: str = ""
    ip: str = ""


@dataclass
class WifiStatus:
    state: str           # IDLE | CONNECTING | CONNECTED | DISCONNECTED | UNAVAILABLE
    ssid: str = ""
    ip: str = ""


def _map_nmcli_error(text: str) -> str:
    t = text.lower()
    if "no network with ssid" in t:
        return "NETWORK_NOT_FOUND"
    if "secrets were required" in t or "psk" in t or "802-1x" in t:
        return "WRONG_PASSWORD"
    if "timeout" in t:
        return "TIMEOUT"
    if "no wi-fi device" in t or ("device" in t and "not found" in t):
        return "NO_WIFI_DEVICE"
    return "CONNECTION_FAILED"


class WifiManager:
    PROFILE = "cardforge-wifi"
    PROFILE_NEW = "cardforge-wifi-new"

    def __init__(self, interface: str, timeout: int) -> None:
        self.iface = interface
        self.timeout = timeout
        self._lock = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    async def _nmcli(self, *args: str, timeout: float = 15) -> tuple[int, str, str]:
        env = {**os.environ, "LC_ALL": "C"}  # mensagens em inglês para o mapeamento
        proc = await asyncio.create_subprocess_exec(
            "nmcli", *args, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise
        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")

    async def _ip(self) -> str:
        _, out, _ = await self._nmcli("-g", "IP4.ADDRESS", "device", "show", self.iface)
        return out.strip().split("|")[0].strip().split("/")[0]

    async def connect(self, ssid: str, password: str) -> WifiResult:
        """Cria um perfil novo; só substitui o anterior se conectar.
        Se falhar, o perfil antigo continua salvo e o NetworkManager volta a ele."""
        async with self._lock:
            try:
                await self._nmcli("connection", "delete", self.PROFILE_NEW)
                try:
                    await self._nmcli("device", "wifi", "rescan", "ifname", self.iface)
                except TimeoutError:
                    pass

                args = ["--wait", str(self.timeout), "device", "wifi", "connect", ssid,
                        "ifname", self.iface, "name", self.PROFILE_NEW]
                if password:
                    args += ["password", password]
                code, out, err = await self._nmcli(*args, timeout=self.timeout + 15)

                if code != 0:
                    await self._nmcli("connection", "delete", self.PROFILE_NEW)
                    detail = (err or out).strip().splitlines()
                    reason = _map_nmcli_error(err or out)
                    log.warning("Wi-Fi '%s' falhou: %s (%s)", ssid, reason,
                                detail[-1] if detail else f"código {code}")
                    return WifiResult(False, reason, ssid)

                await self._nmcli("connection", "delete", self.PROFILE)
                await self._nmcli("connection", "modify", self.PROFILE_NEW,
                                  "connection.id", self.PROFILE, "connection.autoconnect", "yes")
                ip = await self._ip()
                log.info("Wi-Fi conectado em '%s' (IP %s)", ssid, ip or "?")
                return WifiResult(True, "WIFI_CONNECTED", ssid, ip)
            except FileNotFoundError:
                log.error("nmcli não encontrado: instale/ative o NetworkManager")
                return WifiResult(False, "NO_NETWORK_MANAGER", ssid)
            except TimeoutError:
                try:
                    await self._nmcli("connection", "delete", self.PROFILE_NEW)
                except (TimeoutError, OSError):
                    pass
                return WifiResult(False, "TIMEOUT", ssid)

    async def status(self) -> WifiStatus:
        if self.busy:
            return WifiStatus("CONNECTING")
        try:
            _, state, _ = await self._nmcli("-g", "GENERAL.STATE", "device", "show", self.iface)
            if not state.strip().startswith("100"):
                return WifiStatus("DISCONNECTED")
            _, lines, _ = await self._nmcli("-g", "ACTIVE,SSID", "device", "wifi", "list",
                                            "ifname", self.iface, "--rescan", "no")
            ssid = ""
            for line in lines.splitlines():
                if line.startswith("yes:"):
                    ssid = line[4:].replace("\\:", ":").replace("\\\\", "\\")
                    break
            return WifiStatus("CONNECTED", ssid, await self._ip())
        except (OSError, TimeoutError):
            return WifiStatus("UNAVAILABLE")


# =============================================================================
# Validação das entradas vindas do app
# =============================================================================
def valid_ssid(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value.encode()) <= 32
            and all(ch.isprintable() for ch in value))


def valid_wifi_password(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value == "":
        return True                                   # rede aberta
    if HEX64_RE.fullmatch(value):
        return True                                   # PSK em hexadecimal
    return 8 <= len(value) <= 63 and all(32 <= ord(c) <= 126 for c in value)


# =============================================================================
# Servidor BLE
# =============================================================================
class CardForgeBle:
    def __init__(self, cfg: Config, store: UserStore, wifi: WifiManager, guard: AuthGuard) -> None:
        self.cfg = cfg
        self.store = store
        self.wifi = wifi
        self.guard = guard
        self.server: Any = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.session_user: str | None = None
        self.session_until = 0.0
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task] = set()
        self._handlers: dict[str, Callable[[Any, dict], Awaitable[None]]] = {
            "info": self.cmd_info,
            "auth": self.cmd_auth,
            "wifi": self.cmd_wifi,
            "wifi_status": self.cmd_wifi_status,
            "logout": self.cmd_logout,
        }

    # ------------------------------ sessão ---------------------------------
    def authed(self) -> bool:
        return self.session_user is not None and time.monotonic() < self.session_until

    def start_session(self, user: str) -> None:
        self.session_user = user
        self.session_until = time.monotonic() + self.cfg.session_ttl_seconds

    def end_session(self, reason: str) -> None:
        if self.session_user:
            log.info("Sessão de '%s' encerrada (%s)", self.session_user, reason)
        self.session_user = None
        self.session_until = 0.0

    # --------------------------- BLE: entrada/saída -------------------------
    def on_read(self, characteristic: Any, **_: Any) -> bytearray:
        return characteristic.value

    def on_write(self, characteristic: Any, value: Any, **_: Any) -> None:
        if str(characteristic.uuid).lower() != RX_UUID:
            return
        self.spawn(self.process(bytes(value)))

    def spawn(self, coro: Awaitable[None]) -> None:
        assert self.loop is not None
        task = self.loop.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def send(self, message: dict[str, Any]) -> None:
        raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode()
        if len(raw) > MAX_MESSAGE_BYTES:
            log.warning("Resposta com %d bytes excede %d", len(raw), MAX_MESSAGE_BYTES)
        char = self.server.get_characteristic(TX_UUID)
        char.value = bytearray(raw)
        self.server.update_value(SERVICE_UUID, TX_UUID)
        log.debug("TX %s", message.get("code"))

    def reply(self, req_id: Any, cmd: str | None, ok: bool, code: str, **data: Any) -> None:
        self.send({"id": req_id, "cmd": cmd, "ok": ok, "code": code, **data})

    async def process(self, data: bytes) -> None:
        async with self._lock:          # um comando por vez, na ordem de chegada
            await self.handle(data)

    async def handle(self, data: bytes) -> None:
        if len(data) > MAX_INCOMING_BYTES:
            self.reply(None, None, False, "BAD_REQUEST")
            return
        try:
            msg = json.loads(data.decode("utf-8"))
            if not isinstance(msg, dict):
                raise ValueError
        except (UnicodeDecodeError, ValueError):
            self.reply(None, None, False, "BAD_JSON")
            return

        req_id = msg.get("id")
        if not (isinstance(req_id, int) and not isinstance(req_id, bool) and 0 <= req_id < 2**31):
            req_id = None
        cmd = msg.get("cmd")
        handler = self._handlers.get(cmd) if isinstance(cmd, str) else None
        if handler is None:
            self.reply(req_id, None, False, "UNKNOWN_COMMAND")
            return
        try:
            await handler(req_id, msg)
        except Exception:
            log.exception("Erro ao processar '%s'", cmd)
            self.reply(req_id, cmd, False, "INTERNAL_ERROR")

    # ------------------------------ comandos --------------------------------
    async def cmd_info(self, req_id: Any, msg: dict) -> None:
        self.reply(req_id, "info", True, "INFO", name=self.cfg.name, model=self.cfg.model,
                   serial=self.cfg.serial, fw=FIRMWARE_VERSION, protocol=PROTOCOL_VERSION)

    async def cmd_auth(self, req_id: Any, msg: dict) -> None:
        user, password = msg.get("user"), msg.get("password")
        if not (isinstance(user, str) and USERNAME_RE.fullmatch(user)
                and isinstance(password, str) and 1 <= len(password) <= 128):
            self.reply(req_id, "auth", False, "BAD_REQUEST")
            return

        if (wait := self.guard.retry_after()) > 0:
            self.reply(req_id, "auth", False, "AUTH_LOCKED", retry_after=wait)
            return

        ok = await asyncio.to_thread(verify_password, password, self.cfg.password_hash)
        if not ok:
            self.end_session("senha incorreta")
            left = self.guard.register_failure()
            log.warning("Senha incorreta para o usuário '%s'", user)
            if left == 0:
                self.reply(req_id, "auth", False, "AUTH_LOCKED", retry_after=self.guard.retry_after())
            else:
                self.reply(req_id, "auth", False, "AUTH_FAILED", attempts_left=left)
            return

        self.guard.register_success()
        try:
            is_new = await asyncio.to_thread(self.store.add_or_touch, user)
        except UsersFullError:
            log.warning("Limite de usuários atingido; '%s' não registrado", user)
            self.reply(req_id, "auth", False, "USERS_FULL")
            return

        self.start_session(user)
        log.info("Usuário '%s' autenticado (%s)", user, "novo" if is_new else "já permitido")
        self.reply(req_id, "auth", True, "AUTH_OK", machine_id=self.store.machine_id,
                   new_user=is_new, ttl=self.cfg.session_ttl_seconds)

    async def cmd_wifi(self, req_id: Any, msg: dict) -> None:
        if not self.authed():
            self.reply(req_id, "wifi", False, "NOT_AUTHENTICATED")
            return
        ssid, password = msg.get("ssid"), msg.get("password", "")
        if not valid_ssid(ssid) or not valid_wifi_password(password):
            self.reply(req_id, "wifi", False, "BAD_REQUEST")
            return
        if self.wifi.busy:
            self.reply(req_id, "wifi", False, "WIFI_BUSY")
            return

        self.session_until = time.monotonic() + self.cfg.session_ttl_seconds
        log.info("'%s' enviou Wi-Fi '%s'", self.session_user, ssid)
        self.reply(req_id, "wifi", True, "WIFI_CONNECTING", ssid=ssid)
        self.spawn(self._wifi_job(req_id, ssid, password))

    async def _wifi_job(self, req_id: Any, ssid: str, password: str) -> None:
        result = await self.wifi.connect(ssid, password)
        if result.ok:
            self.reply(req_id, "wifi", True, "WIFI_CONNECTED", ssid=result.ssid, ip=result.ip)
        else:
            self.reply(req_id, "wifi", False, "WIFI_FAILED", reason=result.code, ssid=result.ssid)

    async def cmd_wifi_status(self, req_id: Any, msg: dict) -> None:
        st = await self.wifi.status()
        data: dict[str, Any] = {"state": st.state}
        if self.authed() and st.state == "CONNECTED":
            data.update(ssid=st.ssid, ip=st.ip)
        self.reply(req_id, "wifi_status", True, "WIFI_STATUS", **data)

    async def cmd_logout(self, req_id: Any, msg: dict) -> None:
        self.end_session("logout")
        self.reply(req_id, "logout", True, "LOGGED_OUT")

    # ----------------------- detecção de desconexão ------------------------
    async def watch_connection(self) -> None:
        """bless considera conectado quem assinou notificações do TX.
        Quando o app sai, a sessão termina e o último TX é apagado."""
        was_connected = False
        while True:
            connected = await self.server.is_connected()
            if connected and not was_connected:
                log.info("App conectado")
            elif was_connected and not connected:
                log.info("App desconectado")
                self.end_session("desconectou")
                self.server.get_characteristic(TX_UUID).value = bytearray()
            was_connected = connected
            await asyncio.sleep(1)

    # ------------------------------ ciclo de vida ----------------------------
    async def start(self) -> None:
        from bless import BlessServer, GATTAttributePermissions, GATTCharacteristicProperties

        self.loop = asyncio.get_running_loop()
        self.server = BlessServer(name=self.cfg.name, loop=self.loop)
        self.server.read_request_func = self.on_read
        self.server.write_request_func = self.on_write

        props, perms = GATTCharacteristicProperties, GATTAttributePermissions
        await self.server.add_new_service(SERVICE_UUID)
        await self.server.add_new_characteristic(
            SERVICE_UUID, RX_UUID, props.write, None, perms.writeable)
        await self.server.add_new_characteristic(
            SERVICE_UUID, TX_UUID, props.read | props.notify, bytearray(), perms.readable)
        await self.server.start()
        self.spawn(self.watch_connection())
        log.info("Anunciando '%s' por BLE (serviço %s)", self.cfg.name, SERVICE_UUID)

    async def stop(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self.server is not None:
            await self.server.stop()


# =============================================================================
# Comandos de linha
# =============================================================================
def load_env(path_arg: str | None) -> Path | None:
    from dotenv import load_dotenv

    candidates = [Path(path_arg)] if path_arg else (
        [Path(os.environ["CARDFORGE_ENV"])] if os.getenv("CARDFORGE_ENV") else list(DEFAULT_ENV_PATHS))
    for path in candidates:
        if path.is_file():
            load_dotenv(path, override=False)
            return path
    if path_arg:
        raise ConfigError(f"Arquivo de configuração não encontrado: {path_arg}")
    return None


async def run_server(cfg: Config) -> None:
    store = UserStore(cfg.data_dir / "state.json", cfg.max_allowed_users)
    wifi = WifiManager(cfg.wifi_interface, cfg.wifi_connect_timeout)
    app = CardForgeBle(cfg, store, wifi, AuthGuard(cfg.auth_max_attempts, cfg.auth_lockout_seconds))

    st = await wifi.status()
    log.info("Máquina %s | machine_id %s | Wi-Fi: %s %s", cfg.name, store.machine_id,
             st.state, st.ssid)
    await app.start()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()

    log.info("Encerrando...")
    await app.stop()


def cmd_secure_env(path: Path) -> int:
    """Substitui MACHINE_PASSWORD por MACHINE_PASSWORD_HASH no arquivo.
    Gera uma senha aleatória se ela estiver vazia ou com o valor de exemplo."""
    from dotenv import dotenv_values

    values = dotenv_values(path)
    if (values.get("MACHINE_PASSWORD_HASH") or "").strip():
        print("MACHINE_PASSWORD_HASH já definido. Nada a fazer.")
        return 0

    password = values.get("MACHINE_PASSWORD") or ""
    generated = not password or password == PLACEHOLDER_PASSWORD or len(password) < 6
    if generated:
        password = generate_password()

    new_line = f"MACHINE_PASSWORD_HASH={hash_password(password)}"
    out, replaced = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        key = line.strip().removeprefix("export ").split("=", 1)[0].strip()
        if key == "MACHINE_PASSWORD":
            if not replaced:
                out.append(new_line)
                replaced = True
            continue
        if key == "MACHINE_PASSWORD_HASH":
            continue
        out.append(line)
    if not replaced:
        out.append(new_line)

    atomic_write(path, "\n".join(out) + "\n", mode=os.stat(path).st_mode & 0o777)
    print("Senha da máquina protegida com hash.")
    if generated:
        print(f"SENHA GERADA: {password}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CardForge BLE (Raspberry Pi)")
    parser.add_argument("--env", help="arquivo de configuração (.env)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="inicia o servidor BLE (padrão)")
    sub.add_parser("check", help="valida a configuração")
    sub.add_parser("hash-password", help="gera MACHINE_PASSWORD_HASH")
    p_secure = sub.add_parser("secure-env", help="troca a senha em texto puro por hash")
    p_secure.add_argument("file", type=Path)
    args = parser.parse_args()
    command = args.command or "run"

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if command == "hash-password":
        pw = getpass.getpass("Senha da máquina: ")
        if len(pw) < 6 or pw != getpass.getpass("Confirme: "):
            print("Senhas diferentes ou com menos de 6 caracteres.", file=sys.stderr)
            return 1
        print(f"MACHINE_PASSWORD_HASH={hash_password(pw)}")
        return 0
    if command == "secure-env":
        return cmd_secure_env(args.file)

    try:
        env_path = load_env(args.env)
        cfg = Config.from_env()
    except ConfigError as exc:
        log.error("Configuração inválida: %s", exc)
        return 2
    logging.getLogger().setLevel(cfg.log_level)

    if command == "check":
        print(f"OK | arquivo: {env_path} | nome BLE: {cfg.name} | dados: {cfg.data_dir}")
        return 0

    log.info("CardForge BLE %s (protocolo %d) | config: %s",
             FIRMWARE_VERSION, PROTOCOL_VERSION, env_path)
    asyncio.run(run_server(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
