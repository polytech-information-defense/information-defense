"""Настройки процесса fw-integrity.

Файл настроек (по умолчанию /etc/fw/integrity.json) задаёт пути и состав
проверки ОС. Сам файл контролируется как неизменяемый (STATIC).

Период проверки (ЦЛС-03) сюда не входит: его меняет администратор через API,
и он хранится в файле состояния.
"""

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path("/etc/fw/integrity.json")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OsCheckSettings:
    """Проверка состояния ОС по таблице ОБР-02."""

    enabled: bool = False
    ports: tuple[str, ...] = ()            # системные имена обслуживаемых интерфейсов
    service_ifaces: tuple[str, ...] = ()   # служебные TAP-интерфейсы
    nft_table: str = "fw"                  # таблица семейства netdev
    expected_mtu: int = 1500


@dataclass(frozen=True, slots=True)
class Settings:
    config_path: Path = DEFAULT_CONFIG_PATH
    manifest_path: Path = Path("/etc/fw/integrity/manifest.json")
    state_dir: Path = Path("/var/lib/fw/integrity")
    socket_path: Path = Path("/run/fw/integrity.sock")
    socket_group: str | None = "fwapi"
    log_socket: Path = Path("/run/fw/log.sock")
    filter_socket: Path = Path("/run/fw/filter.sock")
    # Службы, которые останавливаются при переходе в аварийный режим и
    # запускаются при выходе из него. Остановка fw-filter оставляет в силе
    # правило drop на netdev ingress, поэтому трафик гарантированно не идёт.
    emergency_stop_units: tuple[str, ...] = ("fw-filter.service", "fw-web.service", "ssh.service")
    pending_timeout_s: float = 60.0      # сколько ждать commit после begin_update
    request_timeout_s: float = 3.0       # тайм-аут обращения к другим подсистемам
    os_check: OsCheckSettings = field(default_factory=OsCheckSettings)


_PATH_FIELDS = {"config_path", "manifest_path", "state_dir", "socket_path", "log_socket", "filter_socket"}


def _build(cls: type, data: dict[str, Any], where: str) -> Any:
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: ожидается объект")
    known = {f.name: f for f in fields(cls)}
    unknown = set(data) - set(known)
    if unknown:
        raise ConfigError(f"{where}: неизвестные параметры {sorted(unknown)}")
    kwargs: dict[str, Any] = {}
    for name, value in data.items():
        if name == "os_check":
            kwargs[name] = _build(OsCheckSettings, value, f"{where}.os_check")
        elif name in _PATH_FIELDS:
            if not isinstance(value, str) or not value.startswith("/"):
                raise ConfigError(f"{where}.{name}: нужен абсолютный путь")
            kwargs[name] = Path(value)
        elif name in {"emergency_stop_units", "ports", "service_ifaces"}:
            if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
                raise ConfigError(f"{where}.{name}: нужен список строк")
            kwargs[name] = tuple(value)
        elif name == "socket_group":
            if value is not None and not isinstance(value, str):
                raise ConfigError(f"{where}.{name}: нужна строка или null")
            kwargs[name] = value
        elif name in {"pending_timeout_s", "request_timeout_s"}:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ConfigError(f"{where}.{name}: нужно положительное число")
            kwargs[name] = float(value)
        elif name == "enabled":
            if not isinstance(value, bool):
                raise ConfigError(f"{where}.{name}: нужно true или false")
            kwargs[name] = value
        elif name == "expected_mtu":
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigError(f"{where}.{name}: нужно положительное целое")
            kwargs[name] = value
        elif name == "nft_table":
            if not isinstance(value, str) or not value:
                raise ConfigError(f"{where}.{name}: нужна непустая строка")
            kwargs[name] = value
    return cls(**kwargs)


def load_settings(path: Path = DEFAULT_CONFIG_PATH) -> Settings:
    """Прочитать настройки. Отсутствующий файл означает настройки по умолчанию."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Settings(config_path=path)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: некорректный JSON: {exc}") from exc
    if isinstance(data, dict):
        data = {**data, "config_path": str(path.absolute())}
    return _build(Settings, data, str(path))
