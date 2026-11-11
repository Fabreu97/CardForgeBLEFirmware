#!/usr/bin/env python3
"""
CardForge BLE - firmware de vinculação da máquina (Raspberry Pi 4B)

Python 3.11+ | bless (servidor GATT sobre BlueZ) | NetworkManager (nmcli) |
cryptography

O app CardForge se comunica com a máquina por Bluetooth Low Energy para
(1) autenticar o usuário com a SENHA DA MÁQUINA (desafio e resposta com HMAC,
nos dois sentidos: o app prova que sabe a senha e a máquina prova ao app que é
autêntica) e (2) enviar o Wi-Fi, CIFRADO com AES-256-GCM, para a máquina se
conectar. A senha e o Wi-Fi nunca trafegam em texto.

O protocolo completo (UUIDs, mensagens, criptografia, vetor de teste, fluxo do
Link Machine) está em CONTRATO_BLE.md.

Comandos:
  python cardforge_ble.py run                 inicia o servidor BLE (padrão)
  python cardforge_ble.py check               valida a configuração (.env)
  python cardforge_ble.py gen-password        gera uma senha forte
  python cardforge_ble.py secure-env ARQUIVO  protege o arquivo (chmod 600) e
                                              gera a senha se ela não existir

Opção global:
  --env ARQUIVO   arquivo de configuração. Padrão: $CARDFORGE_ENV,
                  /etc/cardforge/cardforge.env ou ./.env
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import signal
import struct
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol

if sys.version_info < (3, 11):
    sys.exit("CardForge BLE requer Python 3.11 ou superior.")

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # pragma: no cover
    sys.exit("Falta o pacote 'cryptography'. Instale com: pip install cryptography")

# =============================================================================
# Constantes do protocolo (devem bater com CONTRATO_BLE.md)
# =============================================================================
PROTOCOL_VERSION = 1
FIRMWARE_VERSION = "2.0.0"

SERVICE_UUID = "7f1c0001-5b6e-4a52-9d0e-3c1a8f2b9e10"
RX_UUID = "7f1c0002-5b6e-4a52-9d0e-3c1a8f2b9e10"  # app -> máquina (write)
TX_UUID = "7f1c0003-5b6e-4a52-9d0e-3c1a8f2b9e10"  # máquina -> app (notify)

BLE_CHUNK = 20            # bytes por escrita/notificação (funciona com MTU 23)
CHUNK_PAUSE = 0.02        # pausa entre notificações (s)
MAX_MESSAGE_BYTES = 1024  # limite de uma mensagem, sem contar o "\n"
RX_IDLE_TIMEOUT = 5.0     # descarta mensagem incompleta após 5 s sem dados
CHALLENGE_TTL = 30.0      # tempo para o app responder ao desafio (s)

NONCE_LEN = 16
IV_LEN = 12
MAC_LEN = 32
GCM_TAG_LEN = 16
MAX_CT_BYTES = 512

WIFI_LABEL = b"cardforge/wifi/v1"   # info do HKDF e AAD do AES-GCM
MIN_PASSWORD_LEN = 8
PLACEHOLDER_PASSWORD = "troque-esta-senha"
DEFAULT_ENV_PATHS = (Path("/etc/cardforge/cardforge.env"),
                     Path(__file__).resolve().parent / ".env")

MODEL_RE = re.compile(r"^[A-Za-z0-9-]{1,16}$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
HEX64_RE = re.compile(r"^[0-9A-Fa-f]{64}$")

log = logging.getLogger("cardforge")


class ConfigError(Exception):
    """Configuração inválida no .env."""


# =============================================================================
# Criptografia (idêntica ao contrato; ver o vetor de teste em CONTRATO_BLE.md)
# =============================================================================
def mac_with_prefix(key: bytes, label: str, *parts: bytes) -> bytes:
    """HMAC-SHA256(key) sobre: label || (tamanho de 2 bytes big-endian || parte)..."""
    data = label.encode("ascii")
    for part in parts:
        data += struct.pack(">H", len(part)) + part
    return hmac.new(key, data, hashlib.sha256).digest()


def derive_wifi_key(password: bytes, nonce_s: bytes, nonce_c: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=nonce_s + nonce_c, info=WIFI_LABEL).derive(password)


def decrypt_wifi(key: bytes, iv: bytes, ct: bytes) -> bytes:
    """ct = ciphertext || tag de 16 bytes. Levanta InvalidTag se for adulterado."""
    return AESGCM(key).decrypt(iv, ct, WIFI_LABEL)


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: Any, expected_len: int | None = None,
          max_len: int | None = None) -> bytes:
    if not isinstance(text, str):
        raise ValueError("base64 esperado")
    raw = base64.b64decode(text, validate=True)
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError("tamanho inesperado")
    if max_len is not None and len(raw) > max_len:
        raise ValueError("grande demais")
    return raw


# =============================================================================
# Senha da máquina
# =============================================================================
def generate_password(length: int = 12) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# =============================================================================
# Configuração
# =============================================================================
@dataclass(frozen=True)
class Config:
    model: str
    serial: str
    password: str
    wifi_interface: str
    wifi_connect_timeout: int
    auth_max_attempts: int
    auth_lockout_seconds: int
    session_ttl_seconds: int
    max_allowed_users: int
    data_dir: Path
    log_level: str
    max_saved_networks: int = 5

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

        if text("MACHINE_PASSWORD_HASH"):
            raise ConfigError(
                "MACHINE_PASSWORD_HASH não é mais usado: o protocolo seguro precisa da "
                "senha em texto no arquivo (proteja-o com: secure-env). Defina "
                "MACHINE_PASSWORD e remova o hash.")
        password = os.getenv("MACHINE_PASSWORD", "")
        if not password:
            raise ConfigError("Defina MACHINE_PASSWORD (gere uma com: gen-password)")
        if password == PLACEHOLDER_PASSWORD or len(password) < MIN_PASSWORD_LEN:
            raise ConfigError(
                f"MACHINE_PASSWORD: troque o valor de exemplo (mínimo {MIN_PASSWORD_LEN} "
                "caracteres, o mesmo mínimo do app)")
        if len(password.encode("utf-8")) > 128:
            raise ConfigError("MACHINE_PASSWORD: no máximo 128 bytes")

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
            password=password,
            wifi_interface=iface,
            wifi_connect_timeout=integer("WIFI_CONNECT_TIMEOUT", 20, 5, 120),
            auth_max_attempts=integer("AUTH_MAX_ATTEMPTS", 5, 1, 20),
            auth_lockout_seconds=integer("AUTH_LOCKOUT_SECONDS", 60, 5, 3600),
            session_ttl_seconds=integer("SESSION_TTL_SECONDS", 60, 30, 3600),
            max_allowed_users=integer("MAX_ALLOWED_USERS", 20, 1, 1000),
            max_saved_networks=integer("MAX_SAVED_NETWORKS", 5, 1, 20),
            data_dir=data_dir,
            log_level=level,
        )


# =============================================================================
# Usuários permitidos (JSON com gravação atômica e permissão 600)
# =============================================================================
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
        """Registra o usuário como permitido. Retorna True se for novo.
        Com a lista cheia, remove o usuário visto há mais tempo (não recusa ninguém)."""
        key = username.lower()
        users: dict[str, Any] = self.data["users"]
        now = _now_iso()
        is_new = key not in users
        if is_new:
            while len(users) >= self.max_users:
                oldest = min(users, key=lambda k: users[k].get("last_seen", ""))
                del users[oldest]
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

    def __init__(self, max_attempts: int, lockout_seconds: int,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.clock = clock
        self.fails = 0
        self.lockouts = 0
        self.locked_until = 0.0

    def retry_after(self) -> int:
        remaining = self.locked_until - self.clock()
        return max(0, int(remaining) + (1 if remaining % 1 else 0)) if remaining > 0 else 0

    def register_failure(self) -> tuple[int, int]:
        """Retorna (tentativas restantes, segundos de bloqueio). Bloqueio 0 = não bloqueou."""
        self.fails += 1
        if self.fails >= self.max_attempts:
            self.fails = 0
            self.lockouts += 1
            duration = min(self.lockout_seconds * 2 ** (self.lockouts - 1), self.MAX_LOCK_SECONDS)
            self.locked_until = self.clock() + duration
            log.warning("Muitas senhas erradas: bloqueado por %ss", duration)
            return 0, duration
        return self.max_attempts - self.fails, 0

    def register_success(self) -> None:
        self.fails = 0
        self.lockouts = 0


# =============================================================================
# Wi-Fi (NetworkManager via nmcli, sem shell)
# =============================================================================
@dataclass
class WifiResult:
    ok: bool
    reason: str = ""     # bad_password|ssid_not_found|timeout|connect_failed|
                         # no_wifi_device|nmcli_missing|internal_error
    ssid: str = ""
    ip: str = ""
    saved: bool = False  # a rede ficou salva (reconecta sozinha), mesmo se falhou agora


@dataclass
class WifiStatus:
    state: str           # DISCONNECTED | CONNECTING | CONNECTED | UNAVAILABLE
    ssid: str = ""
    ip: str = ""


def _map_nmcli_error(text: str) -> str:
    t = text.lower()
    if "no network with ssid" in t:
        return "ssid_not_found"
    if "secrets were required" in t or "psk" in t or "802-1x" in t:
        return "bad_password"
    if "timeout" in t:
        return "timeout"
    if "no wi-fi device" in t or ("device" in t and "not found" in t):
        return "no_wifi_device"
    return "connect_failed"


class WifiManager:
    """Conecta no Wi-Fi com o NetworkManager e SALVA a rede mesmo quando a conexão
    falha agora (rede fora de alcance, roteador desligado, sinal ruim...).

    Cada rede tem o seu perfil ("cardforge-wifi-<hash do SSID>") com reconexão
    automática. Mandar a mesma rede de novo troca a senha dela; redes diferentes ficam
    todas salvas (até MAX_SAVED_NETWORKS), então um erro de digitação nunca apaga a
    rede que já funcionava."""

    PROFILE_PREFIX = "cardforge-wifi-"
    PRIORITY = "10"                                   # acima das redes comuns (0)
    # Falhas em que vale salvar a rede para tentar de novo mais tarde.
    SAVE_ON = frozenset({"bad_password", "ssid_not_found", "timeout", "connect_failed"})

    def __init__(self, interface: str, timeout: int, max_saved: int = 5) -> None:
        self.iface = interface
        self.timeout = timeout
        self.max_saved = max_saved
        self._lock = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    @classmethod
    def profile_name(cls, ssid: str) -> str:
        return cls.PROFILE_PREFIX + hashlib.sha1(ssid.encode("utf-8")).hexdigest()[:10]

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

    async def _delete(self, name: str) -> None:
        try:
            await self._nmcli("connection", "delete", name)
        except TimeoutError:
            pass

    async def _save_profile(self, name: str, ssid: str, password: str) -> bool:
        """Cria o perfil sem tentar conectar: funciona com a rede fora de alcance e
        o NetworkManager conecta sozinho quando ela aparecer."""
        try:
            await self._delete(name)                  # sobra de uma tentativa que falhou
            args = ["connection", "add", "type", "wifi", "ifname", self.iface,
                    "con-name", name, "ssid", ssid,
                    "connection.autoconnect", "yes",
                    "connection.autoconnect-priority", self.PRIORITY]
            if password:
                args += ["wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password]
            code, _, err = await self._nmcli(*args)
            if code != 0:
                log.warning("Não foi possível salvar a rede: %s", err.strip())
                return False
            await self._prune(name)
            log.info("Rede salva: a máquina conecta sozinha quando ela estiver disponível")
            return True
        except (OSError, TimeoutError):
            return False

    async def _prune(self, keep: str) -> None:
        """Mantém no máximo max_saved redes do CardForge, apagando as mais antigas."""
        try:
            code, out, _ = await self._nmcli("-t", "-f", "NAME,TIMESTAMP", "connection", "show")
        except (OSError, TimeoutError):
            return
        if code != 0:
            return
        others: list[tuple[int, str]] = []
        for line in out.splitlines():
            name, _, stamp = line.rpartition(":")
            if name.startswith(self.PROFILE_PREFIX) and name != keep:
                others.append((int(stamp) if stamp.isdigit() else 0, name))
        excess = len(others) + 1 - self.max_saved     # +1 conta a rede "keep"
        for _, name in sorted(others)[:max(0, excess)]:
            await self._delete(name)

    async def connect(self, ssid: str, password: str) -> WifiResult:
        async with self._lock:
            name = self.profile_name(ssid)
            try:
                await self._delete(name)              # troca a senha antiga desta rede
                try:
                    await self._nmcli("device", "wifi", "rescan", "ifname", self.iface)
                except TimeoutError:
                    pass

                args = ["--wait", str(self.timeout), "device", "wifi", "connect", ssid,
                        "ifname", self.iface, "name", name]
                if password:
                    args += ["password", password]
                code, out, err = await self._nmcli(*args, timeout=self.timeout + 15)

                if code == 0:
                    await self._nmcli("connection", "modify", name,
                                      "connection.autoconnect", "yes",
                                      "connection.autoconnect-priority", self.PRIORITY)
                    ip = await self._ip()
                    await self._prune(name)
                    log.info("Wi-Fi conectado (IP %s)", ip or "?")
                    return WifiResult(True, "", ssid, ip, saved=True)
                reason = _map_nmcli_error(err or out)
            except FileNotFoundError:
                log.error("nmcli não encontrado: instale/ative o NetworkManager")
                return WifiResult(False, "nmcli_missing", ssid)
            except TimeoutError:
                reason = "timeout"

            # Não conectou agora: guarda a rede mesmo assim (quando faz sentido).
            saved = reason in self.SAVE_ON and await self._save_profile(name, ssid, password)
            log.warning("Falha ao conectar no Wi-Fi: %s (rede %s)", reason,
                        "salva" if saved else "não salva")
            return WifiResult(False, reason, ssid, saved=saved)

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
def valid_user(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 64
            and all(ch.isprintable() for ch in value))


def valid_ssid(value: Any) -> bool:
    # Não pode começar com "-": o nmcli trataria como uma opção.
    return (isinstance(value, str) and 1 <= len(value.encode("utf-8")) <= 32
            and all(ch.isprintable() for ch in value) and not value.startswith("-"))


def valid_wifi_password(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value == "":
        return True                                   # rede aberta
    if HEX64_RE.fullmatch(value):
        return True                                   # PSK em hexadecimal
    return 8 <= len(value) <= 63 and all(32 <= ord(c) <= 126 for c in value)


# =============================================================================
# Enquadramento (framing): JSON compacto ASCII terminado em "\n"
# =============================================================================
def encode_message(message: dict[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def split_chunks(data: bytes, size: int = BLE_CHUNK) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


class FrameReader:
    """Junta os pedaços escritos pelo app e entrega uma mensagem por "\\n".

    feed() devolve, em ordem, cada mensagem completa (bytes) ou None quando uma
    mensagem passou do limite de tamanho."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.last = 0.0

    def clear(self) -> None:
        self.buf.clear()

    def feed(self, data: bytes, now: float) -> list[bytes | None]:
        out: list[bytes | None] = []
        if self.buf and now - self.last > RX_IDLE_TIMEOUT:
            self.buf.clear()                       # mensagem incompleta abandonada
        self.last = now
        self.buf.extend(data)
        while (idx := self.buf.find(b"\n")) >= 0:
            line = bytes(self.buf[:idx])
            del self.buf[:idx + 1]
            if not line.strip():
                continue
            out.append(line if len(line) <= MAX_MESSAGE_BYTES else None)
        if len(self.buf) > MAX_MESSAGE_BYTES:       # sem "\n" à vista: grande demais
            self.buf.clear()
            out.append(None)
        return out


# =============================================================================
# Transporte BLE (interface + implementação com bless)
# =============================================================================
class Transport(Protocol):
    async def notify(self, chunk: bytes) -> None: ...
    async def is_connected(self) -> bool: ...
    def clear_tx(self) -> None: ...


class BlessTransport:
    """Servidor GATT com bless. RX = escrita do app; TX = notificações para o app."""

    def __init__(self, name: str, on_rx: Callable[[bytes], None]) -> None:
        self.name = name
        self.on_rx = on_rx
        self.server: Any = None
        self.loop: asyncio.AbstractEventLoop | None = None

    def _on_read(self, characteristic: Any, **_: Any) -> bytearray:
        return characteristic.value

    def _on_write(self, characteristic: Any, value: Any, **_: Any) -> None:
        if str(characteristic.uuid).lower() != RX_UUID:
            return
        assert self.loop is not None
        # O callback pode vir de outra thread: volta para o loop, mantendo a ordem.
        self.loop.call_soon_threadsafe(self.on_rx, bytes(value))

    async def start(self) -> None:
        from bless import BlessServer, GATTAttributePermissions, GATTCharacteristicProperties

        self.loop = asyncio.get_running_loop()
        self.server = BlessServer(name=self.name, loop=self.loop)
        self.server.read_request_func = self._on_read
        self.server.write_request_func = self._on_write

        props, perms = GATTCharacteristicProperties, GATTAttributePermissions
        await self.server.add_new_service(SERVICE_UUID)
        await self.server.add_new_characteristic(
            SERVICE_UUID, RX_UUID, props.write | props.write_without_response,
            None, perms.writeable)
        await self.server.add_new_characteristic(
            SERVICE_UUID, TX_UUID, props.read | props.notify, bytearray(), perms.readable)
        await self.server.start()
        log.info("Anunciando '%s' por BLE (serviço %s)", self.name, SERVICE_UUID)

    async def stop(self) -> None:
        if self.server is not None:
            await self.server.stop()

    async def notify(self, chunk: bytes) -> None:
        self.server.get_characteristic(TX_UUID).value = bytearray(chunk)
        self.server.update_value(SERVICE_UUID, TX_UUID)

    async def is_connected(self) -> bool:
        return bool(await self.server.is_connected())

    def clear_tx(self) -> None:
        self.server.get_characteristic(TX_UUID).value = bytearray()


# =============================================================================
# Protocolo: máquina de estados da vinculação
# =============================================================================
IDLE, CHALLENGED, AUTHED = "idle", "challenged", "authed"


class CardForgeBle:
    """hello -> challenge -> auth -> auth_ok + wifi_request -> wifi -> wifi_status."""

    def __init__(self, cfg: Config, store: UserStore, wifi: Any, guard: AuthGuard,
                 transport: Transport, *,
                 clock: Callable[[], float] = time.monotonic,
                 rand: Callable[[int], bytes] = secrets.token_bytes,
                 chunk_pause: float = CHUNK_PAUSE) -> None:
        self.cfg = cfg
        self.store = store
        self.wifi = wifi
        self.guard = guard
        self.transport = transport
        self.clock = clock
        self.rand = rand
        self.chunk_pause = chunk_pause
        self.password = cfg.password.encode("utf-8")

        self.reader = FrameReader()
        self._inbox: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._tx_lock = asyncio.Lock()
        self._tasks: set[asyncio.Task] = set()
        self._handlers: dict[str, Callable[[dict], Awaitable[None]]] = {
            "hello": self.on_hello,
            "auth": self.on_auth,
            "wifi": self.on_wifi,
        }
        self._reset_session()

    # ------------------------------ sessão ---------------------------------
    def _reset_session(self) -> None:
        self.state = IDLE
        self.user: str | None = None
        self.nonce_s: bytes | None = None
        self.challenge_at = 0.0
        self.wifi_key: bytes | None = None
        self.session_until = 0.0

    def end_session(self, reason: str) -> None:
        if self.user and self.state == AUTHED:
            log.info("Sessão de '%s' encerrada (%s)", self.user, reason)
        self._reset_session()

    def authed(self) -> bool:
        if self.state != AUTHED:
            return False
        if self.clock() >= self.session_until:
            self.end_session("expirou")
            return False
        return True

    def _touch_session(self) -> None:
        self.session_until = self.clock() + self.cfg.session_ttl_seconds

    # --------------------------- entrada e saída ----------------------------
    def on_rx(self, data: bytes) -> None:
        """Chamado no loop a cada escrita do app (um pedaço de até 20 bytes)."""
        for item in self.reader.feed(data, self.clock()):
            self._inbox.put_nowait(item)

    def on_disconnected(self) -> None:
        log.info("App desconectado")
        self.end_session("desconectou")
        self.reader.clear()
        try:
            self.transport.clear_tx()
        except Exception:
            log.debug("Não foi possível limpar o TX", exc_info=True)

    async def send(self, message: dict[str, Any]) -> None:
        """Envia uma mensagem em pedaços de 20 bytes, sem misturar com outra."""
        data = encode_message(message)
        async with self._tx_lock:
            try:
                for chunk in split_chunks(data):
                    await self.transport.notify(chunk)
                    if self.chunk_pause:
                        await asyncio.sleep(self.chunk_pause)
            except Exception:
                log.debug("Falha ao notificar o app (desconectado?)", exc_info=True)
        log.debug("TX %s", message.get("t"))

    async def send_error(self, code: str, **extra: Any) -> None:
        await self.send({"t": "error", "code": code, **extra})

    def spawn(self, coro: Awaitable[None]) -> None:
        task = asyncio.get_running_loop().create_task(coro)  # type: ignore[arg-type]
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def worker(self) -> None:
        """Processa as mensagens uma por vez, na ordem de chegada."""
        while True:
            raw = await self._inbox.get()
            try:
                await self.handle(raw)
            except Exception:
                log.exception("Erro ao processar mensagem")
                await self.send_error("bad_message")
            finally:
                self._inbox.task_done()

    async def wait_idle(self) -> None:
        """Espera as mensagens e as conexões Wi-Fi em andamento terminarem (testes)."""
        await self._inbox.join()
        while pending := [t for t in self._tasks if not t.done()]:
            await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.sleep(0)        # deixa os callbacks de término rodarem
        await self._inbox.join()

    async def handle(self, raw: bytes | None) -> None:
        if raw is None:
            await self.send_error("bad_message")
            return
        try:
            msg = json.loads(raw.decode("utf-8"))
            if not isinstance(msg, dict):
                raise ValueError
        except (UnicodeDecodeError, ValueError):
            await self.send_error("bad_message")
            return
        t = msg.get("t")
        handler = self._handlers.get(t) if isinstance(t, str) else None
        if handler is None:
            await self.send_error("unknown_type")
            return
        await handler(msg)

    # ------------------------------ mensagens -------------------------------
    async def on_hello(self, msg: dict) -> None:
        v = msg.get("v")
        if type(v) is not int or v != PROTOCOL_VERSION:
            await self.send_error("unsupported_version", supported=[PROTOCOL_VERSION])
            return
        user = msg.get("user")
        if not valid_user(user):
            await self.send_error("bad_user")
            return
        if (wait := self.guard.retry_after()) > 0:
            await self.send_error("locked", retry_in=wait)
            return
        if self.authed():
            await self.send_error("busy")      # outro app já está autenticado
            return

        self._reset_session()
        self.state = CHALLENGED
        self.user = user
        self.nonce_s = self.rand(NONCE_LEN)
        self.challenge_at = self.clock()
        await self.send({"t": "challenge", "v": PROTOCOL_VERSION,
                         "device": self.cfg.name, "nonce": _b64e(self.nonce_s)})

    async def on_auth(self, msg: dict) -> None:
        if (wait := self.guard.retry_after()) > 0:
            self._reset_session()
            await self.send_error("locked", retry_in=wait)
            return
        if (self.state != CHALLENGED or self.nonce_s is None or self.user is None
                or self.clock() - self.challenge_at > CHALLENGE_TTL):
            self._reset_session()
            await self.send_error("bad_message")
            return
        try:
            nonce_c = _b64d(msg.get("nonce_c"), NONCE_LEN)
            mac_c = _b64d(msg.get("mac"), MAC_LEN)
        except ValueError:
            self._reset_session()
            await self.send_error("bad_message")
            return

        nonce_s, user = self.nonce_s, self.user
        self.nonce_s = None                         # o desafio vale uma única vez
        user_b = user.encode("utf-8")
        expected = mac_with_prefix(self.password, "cf-app", nonce_s, nonce_c, user_b)
        if not hmac.compare_digest(expected, mac_c):
            self._reset_session()
            left, retry_in = self.guard.register_failure()
            log.warning("Senha incorreta para o usuário '%s'", user)
            reply: dict[str, Any] = {"t": "auth_fail", "attempts_left": left}
            if retry_in:
                reply["retry_in"] = retry_in
            await self.send(reply)
            return

        self.guard.register_success()
        self.wifi_key = derive_wifi_key(self.password, nonce_s, nonce_c)
        server_mac = mac_with_prefix(self.password, "cf-srv", nonce_c, nonce_s, user_b)
        self.state = AUTHED
        self._touch_session()
        try:
            is_new = await asyncio.to_thread(self.store.add_or_touch, user)
        except OSError:
            log.exception("Não foi possível gravar o usuário")
            is_new = False
        log.info("Usuário '%s' autenticado (%s)", user, "novo" if is_new else "já permitido")
        await self.send({"t": "auth_ok", "mac": _b64e(server_mac)})
        await self.send({"t": "wifi_request"})

    async def on_wifi(self, msg: dict) -> None:
        if not self.authed() or self.wifi_key is None:
            await self.send_error("unauthorized")
            return
        if self.wifi.busy:
            await self.send_error("busy")
            return
        try:
            iv = _b64d(msg.get("iv"), IV_LEN)
            ct = _b64d(msg.get("ct"), max_len=MAX_CT_BYTES)
            if len(ct) <= GCM_TAG_LEN:
                raise ValueError("ct curto demais")
        except ValueError:
            await self.send_error("bad_message")
            return
        try:
            plain = decrypt_wifi(self.wifi_key, iv, ct)
        except InvalidTag:
            await self.send_error("decrypt_failed")
            return
        try:
            data = json.loads(plain.decode("utf-8"))
            ssid, psk = data.get("ssid"), data.get("psk", "")
        except (UnicodeDecodeError, ValueError, AttributeError):
            await self.send_error("invalid_wifi")
            return
        if not valid_ssid(ssid) or not valid_wifi_password(psk):
            await self.send_error("invalid_wifi")
            return

        self._touch_session()
        log.info("'%s' enviou as credenciais de Wi-Fi", self.user)
        await self.send({"t": "wifi_status", "state": "connecting"})
        self.spawn(self._wifi_job(ssid, psk))

    async def _wifi_job(self, ssid: str, psk: str) -> None:
        try:
            result = await self.wifi.connect(ssid, psk)
        except Exception:
            log.exception("Erro inesperado ao conectar no Wi-Fi")
            result = WifiResult(False, "internal_error", ssid)
        if self.state == AUTHED:
            self._touch_session()                   # a conexão pode demorar
        if result.ok:
            await self.send({"t": "wifi_status", "state": "connected", "ip": result.ip})
        else:
            await self.send({"t": "wifi_status", "state": "failed",
                             "reason": result.reason or "connect_failed",
                             "saved": result.saved})

    # ----------------------- detecção de desconexão ------------------------
    async def watch_connection(self) -> None:
        """bless considera conectado quem assinou as notificações do TX."""
        was_connected = False
        while True:
            connected = await self.transport.is_connected()
            if connected and not was_connected:
                log.info("App conectado")
            elif was_connected and not connected:
                self.on_disconnected()
            was_connected = connected
            await asyncio.sleep(1)

    async def start_tasks(self) -> None:
        self.spawn(self.worker())
        self.spawn(self.watch_connection())

    async def stop(self) -> None:
        for task in list(self._tasks):
            task.cancel()


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
    wifi = WifiManager(cfg.wifi_interface, cfg.wifi_connect_timeout, cfg.max_saved_networks)
    guard = AuthGuard(cfg.auth_max_attempts, cfg.auth_lockout_seconds)

    holder: dict[str, CardForgeBle] = {}
    transport = BlessTransport(cfg.name, lambda data: holder["app"].on_rx(data))
    app = CardForgeBle(cfg, store, wifi, guard, transport)
    holder["app"] = app

    st = await wifi.status()
    log.info("Máquina %s | machine_id %s | Wi-Fi: %s %s", cfg.name, store.machine_id,
             st.state, st.ssid)
    await transport.start()
    await app.start_tasks()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()

    log.info("Encerrando...")
    await app.stop()
    await transport.stop()


def cmd_secure_env(path: Path) -> int:
    """Deixa o arquivo legível só pelo dono (chmod 600) e gera uma senha forte se
    MACHINE_PASSWORD estiver vazia, com o valor de exemplo ou curta demais."""
    from dotenv import dotenv_values

    values = dotenv_values(path)
    password = values.get("MACHINE_PASSWORD") or ""
    generated = (not password or password == PLACEHOLDER_PASSWORD
                 or len(password) < MIN_PASSWORD_LEN)
    lines = path.read_text(encoding="utf-8").splitlines()
    if generated:
        password = generate_password()
        out, replaced = [], False
        for line in lines:
            key = line.strip().removeprefix("export ").split("=", 1)[0].strip()
            if key == "MACHINE_PASSWORD":
                if not replaced:
                    out.append(f"MACHINE_PASSWORD={password}")
                    replaced = True
                continue
            out.append(line)
        if not replaced:
            out.append(f"MACHINE_PASSWORD={password}")
        lines = out
    atomic_write(path, "\n".join(lines) + "\n", mode=0o600)
    print("Arquivo protegido (permissão 600).")
    if generated:
        print(f"SENHA GERADA: {password}")
        print("Anote-a: é a senha que o usuário digita no app (não será mostrada de novo).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CardForge BLE (Raspberry Pi)")
    parser.add_argument("--env", help="arquivo de configuração (.env)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="inicia o servidor BLE (padrão)")
    sub.add_parser("check", help="valida a configuração")
    sub.add_parser("gen-password", help="gera uma senha forte")
    p_secure = sub.add_parser("secure-env", help="protege o arquivo de configuração")
    p_secure.add_argument("file", type=Path)
    args = parser.parse_args()
    command = args.command or "run"

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if command == "gen-password":
        print(generate_password())
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
        if env_path and env_path.stat().st_mode & 0o077:
            print(f"AVISO: {env_path} pode ser lido por outros usuários. "
                  f"Rode: python cardforge_ble.py secure-env {env_path}")
        return 0

    log.info("CardForge BLE %s (protocolo %d) | config: %s",
             FIRMWARE_VERSION, PROTOCOL_VERSION, env_path)
    asyncio.run(run_server(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())