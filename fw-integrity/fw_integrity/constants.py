"""Константы подсистемы: коды событий (приложение А ТЗ), коды ошибок (АПИ-09)."""

from enum import IntEnum, StrEnum

SUBSYSTEM = "integrity"

# ЦЛС-03: период автоматической проверки, минуты
PERIOD_MIN = 1
PERIOD_MAX = 1440
PERIOD_DEFAULT = 10


class Event(IntEnum):
    """Коды событий журнала, которые формирует подсистема."""

    ACCESS_DENIED = 106       # отказ в выполнении функции (недостаточно прав)
    PARAMS_CHANGED = 416      # изменение параметров контроля целостности
    CHECK_OK = 500            # проверка завершена успешно
    VIOLATION = 501           # выявлено нарушение целостности
    EMERGENCY_ENTER = 502     # переход в аварийный режим, блокировка трафика
    FILE_RESTORED = 503       # восстановление файла из резервной копии
    EMERGENCY_LEAVE = 504     # выход из аварийного режима
    REFERENCE_UPDATED = 505   # обновление эталонных значений


class ErrorCode(StrEnum):
    """Машинные коды ошибок API (АПИ-09)."""

    BAD_REQUEST = "bad_request"
    UNKNOWN_COMMAND = "unknown_command"
    INVALID_PARAMS = "invalid_params"
    NOT_FOUND = "not_found"
    VERSION_CONFLICT = "version_conflict"
    FORBIDDEN = "forbidden"
    INTERNAL = "internal"
    INVALID_STATE = "invalid_state"   # команда недопустима в текущем режиме


class Mode(StrEnum):
    NORMAL = "normal"
    EMERGENCY = "emergency"


class Kind(StrEnum):
    """Вид контролируемого файла.

    STATIC -- исполняемые и неизменяемые файлы: меняются только при установке
              ПО МЭ, эталон формирует команда ``init``;
    CONFIG -- конфигурационные файлы, которые подсистемы меняют легитимно
              (ЦЛС-02) через begin_update / commit_update.
    """

    STATIC = "static"
    CONFIG = "config"


class Role(StrEnum):
    """Уровни прав администратора (ДСТ-03)."""

    RW = "rw"   # ЧЗ
    RO = "ro"   # ТЧ
