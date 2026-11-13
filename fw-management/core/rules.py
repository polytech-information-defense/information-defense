import json
import os
import ipaddress
from pathlib import Path
import re

# Путь к файлу конфигурации
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config" / "config.json"

# ---------------------------------------------------------------------------
# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Читает весь config.json."""
    if not os.path.exists(CONFIG_FILE):
        # Если файла нет, создаем базовую структуру (по УПР-11)
        return {"rules": [], "interfaces": {}, "routes": [], "state_control": {}, "logging": {}, "integrity": {}, "session_params": {}}
    
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def _save_config(config: dict):
    """Сохраняет обновленный конфиг в файл."""
    # Согласно ФЛТ-02: правила должны быть отсортированы по возрастанию номеров
    if "rules" in config:
        config["rules"].sort(key=lambda x: x["num"])
    # При открытии файла на запись, файл полностью стирается и в него записывается config
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

def _validate_rule(rule: dict, existing_rules: list, is_edit: bool = False) -> tuple[bool, str]:
    """
    Валидация правила согласно НДЖ-04, ФЛТ-05, ФЛТ-09.
    Возвращает (True, "") если всё ок, или (False, "Причина ошибки").
    """
    # Проверка уникальности номера (ФЛТ-02)
    if not is_edit:
        if rule["num"] < 1:
            return False, f"Номер правила должен быть не меньше 0."
        for r in existing_rules:
            if r["num"] == rule["num"]:
                return False, f"Правило с номером {rule['num']} уже существует."

    # Проверка действий (ФЛТ-07, ФЛТ-08, ФЛТ-09)
    action = rule.get("action")
    if action == "jump":
        jump_num = rule.get("jump")
        if jump_num is None:
            return False, "Для действия 'jump' необходимо указать номер правила перехода (--jump)."
        if jump_num <= rule["num"]:
            return False, "Номер правила перехода должен быть больше номера текущего правила (исключение зацикливания)."
        if rule.get("out") is not None:
            return False, "Для действия 'jump' нельзя указывать выходной интерфейс."
    elif action == "pass":
        if not rule.get("out"):
            return False, "Для действия 'pass' необходимо указать выходной интерфейс (--out)."
        if rule.get("jump") is not None:
            return False, "Для действия 'pass' нельзя указывать номер перехода."           
    elif action == "drop":
        if rule.get("out") is not None or rule.get("jump") is not None:
            return False, "Для действия 'drop' нельзя указывать выходной интерфейс или переход."
    else:
        return False, "Введено некорректное действие. Допустимые действия: 'pass', 'drop', 'jump'"

    # Проверка входного интерфейса
    interface_in = rule.get("in")
    interface_in_pattern = r"^(any|port[1-6](,port[1-6])*)$"
    if not re.match(interface_in_pattern, interface_in):
        return False, "Введен некорректный входной интерфейс. Допустимые интерфейсы: 'any' или port1...port6 (1 или несколько)"

    # Проверка МАС-адреса источника
    src_mac = rule.get("src_mac")
    src_mac_pattern = r"^(any|([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))$"
    if not re.match(src_mac_pattern, src_mac):
        return False, "Введен некорректный МАС-адрес источника. Допустимый формат: XX:XX:XX:XX:XX:XX или XX-XX-XX-XX-XX-XX"

    # Проверка МАС-адреса приёмника
    dst_mac = rule.get("dst_mac")
    dst_mac_pattern = r"^(any|([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))$"
    if not re.match(dst_mac_pattern, dst_mac):
        return False, "Введен некорректный МАС-адрес приёмника. Допустимый формат: XX:XX:XX:XX:XX:XX или XX-XX-XX-XX-XX-XX"

    # Проверка IPv4-адреса источника
    src_ip = rule.get("src_ip")
    src_ip_pattern = r"^(any|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/(3[0-2]|[12]?[0-9]))?)$"
    if not re.match(src_ip_pattern, src_ip):
        return False, "Введен некорректный IP-адрес источника. Допустимый формат: IPv4 (X.X.X.X, где X = 0-255) или CIDR (X.X.X.X/Y, где Y = 0-32)."

    # Проверка IPv4-адреса приёмника
    dst_ip = rule.get("dst_ip")
    dst_ip_pattern = r"^(any|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/(3[0-2]|[12]?[0-9]))?)$"
    if not re.match(dst_ip_pattern, dst_ip):
        return False, "Введен некорректный IP-адрес приёмника. Допустимый формат: IPv4 (X.X.X.X, где X = 0-255) или CIDR (X.X.X.X/Y, где Y = 0-32)."
   
    # Проверка протоколов
    proto = rule.get("proto")
    src_port = rule.get("src_port")
    dst_port = rule.get("dst_port")
    icmp_type = rule.get("icmp_type")
    icmp_code = rule.get("icmp_code")

    # Приводим протокол к строке для удобства
    proto_str = str(proto).lower()

    match proto_str:
        case "icmp":
            if src_port != "any" or dst_port != "any":
                return False, "Для ICMP нельзя указывать порты."
        case "tcp" | "udp":
            if icmp_type != "any" or icmp_code != "any":
                return False, "Тип и код ICMP можно указывать только для ICMP."
        case "any":
            if icmp_type != "any" or icmp_code != "any":
                return False, "Тип и код ICMP можно указывать только для ICMP."
            if src_port != "any" or dst_port != "any":
                return False, "При протоколе 'any' нельзя указывать порты."

        # Номер протокола (числа от 0 до 255)
        case _:
            # Проверяем, является ли протокол числом от 0 до 255
            try:
                proto_num = int(proto_str)
                if not (0 <= proto_num <= 255):
                    return False, f"Номер протокола {proto_num} должен быть в диапазоне 0-255."
            except ValueError:
                return False, f"Неизвестный протокол: '{proto}'. Допустимо 0-255 или tcp/udp/icmp/any."

    # Проверка портов
    if proto_str != "icmp":
        port_pattern = r"^(any|([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])-([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))$"
        for port_val, port_name in [(src_port, "src_port"), (dst_port, "dst_port")]:
            # Значение любой допстимо, не требует проверок
            if port_val == "any":
                continue 
            # Проверка, если указано число (int)
            if isinstance(port_val, int):
                if not (1 <= port_val <= 65535):
                    return False, f"Номер порта ({port_name}) должен быть в диапазоне 1-65535."   
            # Проверка, если указана строка (string)
            elif isinstance(port_val, str):
                # Если это просто число в виде строки (например, "80")
                if port_val.isdigit():
                    if not (1 <= int(port_val) <= 65535):
                         return False, f"Номер порта ({port_name}) должен быть в диапазоне 1-65535."
                # Если это диапазон (например, "1024-2048")
                elif re.match(port_pattern, port_val):
                    start, end = map(int, port_val.split('-'))
                    if not (1 <= start <= end <= 65535):
                        return False, f"Диапазон портов ({port_name}) должен быть в пределах 1-65535 и начало <= конца."
                else:
                    return False, f"Некорректный формат порта ({port_name}). Допустимо: число, диапазон 'X-Y' ('X<=Y') или 'any'."
            # Если указан None или другой тип
            else:
                return False, f"Некорректный тип данных для порта ({port_name})."


    # Проверка типа и кода ICMPv4
    if proto_str == "icmp":
        for icmp_val, icmp_name in [(icmp_type, "icmp_type"), (icmp_code, "icmp_code")]:
            # Значение любой допстимо, не требует проверок
            if icmp_val == "any":
                continue 
            # Проверка, если указано число (int)
            if isinstance(icmp_val, int):
                if not (0 <= icmp_val <= 255):
                    obj_name = "типа" if icmp_name == "icmp_type" else "кода"
                    return False, f"Номер {obj_name} ({icmp_name}) должен быть в диапазоне 0-255."            
            # Если указан None или другой тип
            else:
                return False, f"Некорректный тип данных для поля ({icmp_name})."
            
    # Проверка выходного интерфейса
    interface_out = rule.get("out")
    if interface_out is not None:
        interface_out_pattern = r"^(any|port[1-6](,port[1-6])*)$"
        if not re.match(interface_out_pattern, interface_out):
            return False, "Введен некорректный выходной интерфейс. Допустимые интерфейсы: 'any' или port1...port6 (1 или несколько)"
    
    # Проверка флага контроля состояния
    stateful = rule.get("stateful")
    if not isinstance(stateful, bool):
        return False, f"Флаг контроля состояния ({stateful}) должен быть булевым значением (true/false)."

    # Проверка флага активности
    active = rule.get("active")
    if not isinstance(active, bool):
        return False, f"Флаг активности ({active}) должна быть булевым значением (true/false)."

    # Проверка флага регистрации
    log = rule.get("log")
    if not isinstance(log, bool):
        return False, f"Флаг регистрации ({log}) должна быть булевым значением (true/false)."

    # Проверка комментария
    comment = rule.get("comment")
    if isinstance(comment, str):
        if len(comment)>255:
            return False, f"Комментарий должен быть длиной до 255 символов."    
    else:
        return False, f"Комментарий ({comment}) должен быть строкой."

        # Проверка NAT (кросс-валидация)
    nat_type = rule.get("nat_type")
    nat_ip = rule.get("nat_ip")

    if nat_type in ["snat", "dnat"]:
        if not nat_ip or not isinstance(nat_ip, str):
            return False, "Для SNAT/DNAT необходимо указать IP-адрес в формате строки."
        nat_ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" 
        if not re.match(nat_ip_pattern, nat_ip):
            return False, f"Введен некорректный IP-адрес NAT ({nat_ip}). Допустимый формат: IPv4 (X.X.X.X, где X = 0-255)."
    elif nat_type is None:
        if nat_ip is not None:
            return False, "При отсутствии трансляции (nat_type=None) IP-адрес NAT не должен быть указан."
    else:
        return False, f"Тип NAT ({nat_type}) должен быть либо 'snat', либо 'dnat', либо None."

    return True, ""

# ---------------------------------------------------------------------------
# --- ОСНОВНЫЕ ФУНКЦИИ УПРАВЛЕНИЯ ПРАВИЛАМИ ---
# ---------------------------------------------------------------------------

def show_rules(num: int = None) -> dict:
    """Просмотр всех или одного правила."""
    # Получаем все имеющиеся правила
    config = _load_config()
    rules = config.get("rules", [])

    # Если был задан номер правила, пытаемся найти его и вывести
    if num is not None:
        for r in rules:
            if r["num"] == num:
                return {"status": "success", "code": 0, "data": r}
        return {"status": "error", "code": 0, "reason": f"Правило №{num} не найдено."}

    # Если номер правила не был задан, выводим все правила
    return {"status": "success", "code": 0, "data": rules}


def add_rule(rule_data: dict) -> dict:
    """Добавление нового правила."""
    # Получаем все имеющиеся правила
    config = _load_config()
    rules = config.get("rules", [])
    
    # Заполняем значения по умолчанию, если чего-то нет (чтобы JSON был заполнен полностью)
    defaults = {
        "in": "any", "src_mac": "any", "dst_mac": "any", "src_ip": "any",
        "dst_ip": "any", "proto": "any", "src_port": "any", "dst_port": "any",
        "icmp_type": "any", "icmp_code": "any", "out": None, "jump": None,
        "stateful": False, "active": True, "log": True, "comment": "",
        "nat_type": None, "nat_ip": None
    }
    # Объединяем дефолты и пришедшие данные (пришедшие важнее)
    full_rule = {**defaults, **rule_data}
    print(full_rule)
    
    # Валидация
    is_valid, error_msg = _validate_rule(full_rule, rules)
    if not is_valid:
        return {"status": "error", "code": 300, "description": "Добавление правила", "reason": error_msg}
        
    # Добавление и сохранение
    rules.append(full_rule)
    config["rules"] = rules
    _save_config(config)
    
    return {"status": "success", "code": 300, "description": "Добавление правила"}

def edit_rule(num: int, update_data: dict) -> dict:
    """Изменение существующего правила."""
    # Получаем все имеющиеся правила
    config = _load_config()
    rules = config.get("rules", [])

    # Находим по номеру правило, которое нужно изменить
    rule_to_edit = None
    for r in rules:
        if r["num"] == num:
            rule_to_edit = r
            break

    # Не нашли       
    if not rule_to_edit:
        return {"status": "error", "code": 301, "description": "Изменение правила", "reason": f"Правило №{num} не найдено."}
        
    # Обновляем только переданные поля
    updated_rule = {**rule_to_edit, **update_data}
    
    # Проводим валидацию с флагом изменения правила (is_edit=True)
    is_valid, error_msg = _validate_rule(updated_rule, rules, is_edit=True)
    if not is_valid:
        return {"status": "error", "code": 301, "description": "Изменение правила", "reason": error_msg}
        
    # Применяем изменения
    rules = [updated_rule if r["num"] == num else r for r in rules]
    config["rules"] = rules
    _save_config(config)
    
    return {"status": "success", "code": 301, "description": "Изменение правила"}

def delete_rule(num: int) -> dict:
    """Удаление правила."""
    # Получаем все имеющиеся правила
    config = _load_config()
    rules = config.get("rules", [])

    # Если нечего удалять, то ошибка
    if not any(r["num"] == num for r in rules):
        return {"status": "error", "code": 302, "description": "Удаление правила", "reason": f"Правило №{num} не найдено."}

    # Либо сохраняем все правила без удаленного
    config["rules"] = [r for r in rules if r["num"] != num]
    _save_config(config)
    
    return {"status": "success", "code": 302, "description": "Удаление правила"}

def renumber_rule(old_num: int, new_num: int) -> dict:
    """Перенумерация правила."""
    # Получаем все имеющиеся правила
    config = _load_config()
    rules = config.get("rules", [])
    
    if any(r["num"] == new_num for r in rules):
        return {"status": "error", "code": 303, "description": "Перенумерация правил", "reason": f"Правило с номером {new_num} уже существует."}
        
    rule_to_edit = next((r for r in rules if r["num"] == old_num), None)
    if not rule_to_edit:
        return {"status": "error", "code": 303, "description": "Перенумерация правил", "reason": f"Правило №{old_num} не найдено."}
        
    rule_to_edit["num"] = new_num
    _save_config(config) # При сохранении функция _save_config сама отсортирует правила
    
    return {"status": "success", "code": 303, "description": "Перенумерация правил"}

def toggle_rule(num: int) -> dict:
    """Активация / деактивация правила."""
    # Получаем все имеющиеся правила
    config = _load_config()
    rules = config.get("rules", [])
    
    rule_to_toggle = next((r for r in rules if r["num"] == num), None)
    if not rule_to_toggle:
        return {"status": "error", "code": 304, "description": "Активация / деактивация правила", "reason": f"Правило №{num} не найдено."}
        
    rule_to_toggle["active"] = not rule_to_toggle["active"]
    _save_config(config)
    
    action_word = "активировано" if rule_to_toggle["active"] else "деактивировано"
    return {"status": "success", "code": 304, "description": f"Правило {action_word}"}

    