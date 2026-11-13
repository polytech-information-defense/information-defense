import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from unittest.mock import patch
from core import rules 

# ==========================================
# ФИКСТУРЫ И БАЗОВЫЕ ДАННЫЕ
# ==========================================

# Базовое валидное правило для тестов
VALID_RULE = {
    "num": 10, "action": "pass", "in": "port1", "src_mac": "any", "dst_mac": "any",
    "src_ip": "192.168.1.0/24", "dst_ip": "any", "proto": "tcp", "src_port": "any",
    "dst_port": 80, "icmp_type": "any", "icmp_code": "any", "out": "port2", "jump": None,
    "stateful": True, "active": True, "log": False, "comment": "Test rule",
    "nat_type": None, "nat_ip": None
}

@pytest.fixture
def empty_config():
    return {"rules": [], "interfaces": {}, "routes": [], "state_control": {}, "logging": {}, "integrity": {}, "session_params": {}}

@pytest.fixture
def config_with_rule():
    return {"rules": [VALID_RULE.copy()], "interfaces": {}, "routes": [], "state_control": {}, "logging": {}, "integrity": {}, "session_params": {}}


# ==========================================
# ТЕСТЫ ВАЛИДАТОРА (_validate_rule)
# ==========================================

def test_validate_rule_ideal_success():
    """Проверка, что идеальное правило проходит валидацию (базовый тест)."""
    is_valid, msg = rules._validate_rule(VALID_RULE, existing_rules=[])
    assert is_valid is True
    assert msg == ""

# --- 1. num ---
def test_validate_num_valid():
    rule = {**VALID_RULE, "num": 15}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True
    assert msg == ""

def test_validate_num_invalid():
    rule = {**VALID_RULE, "num": -5}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert msg =="Номер правила должен быть не меньше 0."

def test_validate_num_duplicate_invalid():
    existing = [{"num": 10}]
    rule = {**VALID_RULE, "num": 10}
    # При добавлении (is_edit=False)
    is_valid, msg = rules._validate_rule(rule, existing_rules=existing, is_edit=False)
    assert is_valid is False
    assert "уже существует" in msg
    # При редактировании (is_edit=True) ошибки быть не должно
    is_valid, msg = rules._validate_rule(rule, existing_rules=existing, is_edit=True)
    assert is_valid is True
    assert msg == ""

# --- 2. action ---
@pytest.mark.parametrize("valid_action", ["pass", "drop", "jump"])
def test_validate_action_valid(valid_action):
    rule = {**VALID_RULE, "action": valid_action}
    if valid_action == "jump":
        rule["jump"] = 20
        rule["out"] = None
    elif valid_action == "drop":
        rule["out"] = None 
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"
    assert msg == ""

def test_validate_action_invalid():
    rule = {**VALID_RULE, "action": "invalid_action"}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "Введено некорректное действие" in msg

def test_validate_action_logic_invalid():
    """Проверка всех возможных ошибок логики действий (ФЛТ-07, ФЛТ-08, ФЛТ-09)."""
    
    # === 1. Действие PASS ===
    # 1.1. Pass без out
    rule = {**VALID_RULE, "action": "pass", "out": None, "jump": None}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "необходимо указать выходной интерфейс" in msg

    # 1.2. Pass с указанным jump (нельзя)
    rule = {**VALID_RULE, "action": "pass", "out": "port1", "jump": 20}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "нельзя указывать номер перехода" in msg

    # === 2. Действие JUMP ===
    # 2.1. Jump без jump (None)
    rule = {**VALID_RULE, "action": "jump", "out": None, "jump": None}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "необходимо указать номер правила перехода" in msg

    # 2.2. Jump меньше или равен текущему num (исключение зацикливания)
    rule = {**VALID_RULE, "action": "jump", "num": 10, "jump": 10, "out": None}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "должен быть больше номера текущего" in msg

    # 2.3. Jump с указанным out (нельзя)
    rule = {**VALID_RULE, "action": "jump", "out": "port1", "jump": 20}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "нельзя указывать выходной интерфейс" in msg

    # === 3. Действие DROP ===
    # 3.1. Drop с указанным out (нельзя)
    rule = {**VALID_RULE, "action": "drop", "out": "port1", "jump": None}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "нельзя указывать выходной интерфейс или переход" in msg

    # 3.2. Drop с указанным jump (нельзя)
    rule = {**VALID_RULE, "action": "drop", "out": None, "jump": 20}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "нельзя указывать выходной интерфейс или переход" in msg

    # === 4. НЕИЗВЕСТНОЕ ДЕЙСТВИЕ ===
    rule = {**VALID_RULE, "action": "allow", "out": "port1", "jump": None}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "Введено некорректное действие" in msg

# --- 3. in ---
@pytest.mark.parametrize("valid_in", ["any", "port1", "port6", "port1,port2"])
def test_validate_in_valid(valid_in):
    rule = {**VALID_RULE, "in": valid_in}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"
    assert msg == ""

@pytest.mark.parametrize("invalid_in", ["port7", "port0", "port1,", "any,port1", "port 1", "QQ"])
def test_validate_in_invalid(invalid_in):
    rule = {**VALID_RULE, "in": invalid_in}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "входной интерфейс" in msg

# --- 4. src_mac / 5. dst_mac ---
@pytest.mark.parametrize("valid_mac", ["any", "00:1A:2B:3C:4D:5E", "aa-bb-cc-dd-ee-ff"])
def test_validate_mac_valid(valid_mac):
    rule = {**VALID_RULE, "src_mac": valid_mac, "dst_mac": valid_mac}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"
    assert msg == ""

@pytest.mark.parametrize("invalid_mac", ["00:1A:2B:3C:4D", "00.1A.2B.3C.4D.5E", "GG:1A:2B:3C:4D:5E", "QQ"])
def test_validate_mac_invalid(invalid_mac):
    rule_src = {**VALID_RULE, "src_mac": invalid_mac}
    is_valid, msg = rules._validate_rule(rule_src, existing_rules=[])
    assert is_valid is False
    assert "МАС-адрес источника" in msg
    
    rule_dst = {**VALID_RULE, "dst_mac": invalid_mac}
    is_valid, msg = rules._validate_rule(rule_dst, existing_rules=[])
    assert is_valid is False
    assert "МАС-адрес приёмника" in msg

# --- 6. src_ip / 7. dst_ip ---
@pytest.mark.parametrize("valid_ip", ["any", "192.168.1.1", "0.0.0.0", "255.255.255.255", "10.0.0.0/8", "192.168.1.0/24"])
def test_validate_ip_valid(valid_ip):
    rule = {**VALID_RULE, "src_ip": valid_ip, "dst_ip": valid_ip}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"

@pytest.mark.parametrize("invalid_ip", ["256.1.1.1", "192.168.1", "192.168.1.1/33", "abc", "1.1.1.1/abc", "QQ"])
def test_validate_ip_invalid(invalid_ip):
    rule_src = {**VALID_RULE, "src_ip": invalid_ip}
    is_valid, msg = rules._validate_rule(rule_src, existing_rules=[])
    assert is_valid is False
    assert "IP-адрес источника" in msg
    
    rule_dst = {**VALID_RULE, "dst_ip": invalid_ip}
    is_valid, msg = rules._validate_rule(rule_dst, existing_rules=[])
    assert is_valid is False
    assert "IP-адрес приёмника" in msg

# --- 8. proto (в связке с 9. src_port, 10. dst_port, 11. icmp_type, 12. icmp_code) ---
@pytest.mark.parametrize("proto, src_port, dst_port, icmp_type, icmp_code", [
    ("icmp", "any", "any", 8, 0),
    ("icmp", "any", "any", "any", "any"),
    ("tcp", 12345, "80", "any", "any"),
    ("tcp", "1024-2048", "any", "any", "any"),
    ("udp", "any", 53, "any", "any"),
    ("any", "any", "any", "any", "any")
])
def test_validate_proto_and_ports_valid(proto, src_port, dst_port, icmp_type, icmp_code):
    rule = {**VALID_RULE, "proto": proto, "src_port": src_port, "dst_port": dst_port, 
            "icmp_type": icmp_type, "icmp_code": icmp_code}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Правило должно быть валидным, но получена ошибка: {msg}"

@pytest.mark.parametrize("proto, src_port, dst_port, icmp_type, icmp_code, expected_error", [
    ("icmp", 80, "any", "any", "any", "Для ICMP нельзя указывать порты."),
    ("icmp", "any", "1024-2048", 0, 0, "Для ICMP нельзя указывать порты."),
    ("tcp", "any", 80, 8, "any", "Тип и код ICMP можно указывать только для ICMP."),
    ("udp", "any", 53, "any", 0, "Тип и код ICMP можно указывать только для ICMP."),
    ("any", 80, "any", "any", "any", "При протоколе 'any' нельзя указывать порты."),
    ("any", "any", "any", 8, 0, "Тип и код ICMP можно указывать только для ICMP.")
])
def test_validate_proto_and_ports_invalid(proto, src_port, dst_port, icmp_type, icmp_code, expected_error):
    rule = {**VALID_RULE, "proto": proto, "src_port": src_port, "dst_port": dst_port, 
            "icmp_type": icmp_type, "icmp_code": icmp_code}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert expected_error in msg, f"Ожидалась ошибка '{expected_error}', но получено: '{msg}'"

@pytest.mark.parametrize("valid_port", [1, 65535, "80", "1000-2000"])
def test_validate_ports_boundary_valid(valid_port):
    rule = {**VALID_RULE, "dst_port": valid_port}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True

@pytest.mark.parametrize("invalid_port", [-1, 0, 65536, 99999, "abc", "10-5", "QQ"])
def test_validate_ports_boundary_invalid(invalid_port):
    rule = {**VALID_RULE, "dst_port": invalid_port}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "порт" in msg or "Порт" in msg

@pytest.mark.parametrize("valid_icmp", ["any", 0, 8, 255])
def test_validate_icmp_boundary_valid(valid_icmp):
    rule = {**VALID_RULE, "proto": "icmp", "src_port": "any", "dst_port": "any", 
            "icmp_type": valid_icmp, "icmp_code": valid_icmp}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"

@pytest.mark.parametrize("invalid_icmp", [-1, 256, "abc", None])
def test_validate_icmp_boundary_invalid(invalid_icmp):
    rule = {**VALID_RULE, "proto": "icmp", "src_port": "any", "dst_port": "any", 
            "icmp_type": invalid_icmp}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "ICMP" in msg or "типа" in msg or "данных" in msg

# --- 13. out ---
def test_validate_out_valid():
    rule = {**VALID_RULE, "out": "port1,port2"}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True

def test_validate_out_invalid():
    rule = {**VALID_RULE, "out": "port7"}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "интерфейс" in msg or "порт" in msg

# --- 14. jump ---
def test_validate_jump_valid():
    rule = {**VALID_RULE, "action": "jump", "out": None, "jump": 20}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True

def test_validate_jump_invalid():
    rule = {**VALID_RULE, "action": "jump", "out": None, "jump": 5} # меньше текущего num=10
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "должен быть больше номера текущего" in msg

# --- 15. stateful / 16. active / 17. log ---
@pytest.mark.parametrize("flag_name", ["stateful", "active", "log"])
@pytest.mark.parametrize("valid_bool", [True, False])
def test_validate_bool_flags_valid(flag_name, valid_bool):
    rule = {**VALID_RULE, flag_name: valid_bool}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"

@pytest.mark.parametrize("flag_name", ["stateful", "active", "log"])
@pytest.mark.parametrize("invalid_bool", [1, 0, "true", None])
def test_validate_bool_flags_invalid(flag_name, invalid_bool):
    rule = {**VALID_RULE, flag_name: invalid_bool}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "булевым" in msg

# --- 18. comment ---
@pytest.mark.parametrize("valid_comment", ["", "Тест", "A" * 255])
def test_validate_comment_valid(valid_comment):
    rule = {**VALID_RULE, "comment": valid_comment}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"

@pytest.mark.parametrize("invalid_comment", ["A" * 256, 123, True, None])
def test_validate_comment_invalid(invalid_comment):
    rule = {**VALID_RULE, "comment": invalid_comment}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "Комментарий" in msg

# --- 19. nat_type / 20. nat_ip ---
@pytest.mark.parametrize("nat_type, nat_ip", [
    (None, None),
    ("snat", "8.8.8.8"),
    ("dnat", "10.0.0.1")
])
def test_validate_nat_valid(nat_type, nat_ip):
    rule = {**VALID_RULE, "nat_type": nat_type, "nat_ip": nat_ip}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is True, f"Ошибка: {msg}"

@pytest.mark.parametrize("nat_type, nat_ip", [
    ("snat", None),       # Указан тип, но нет IP
    ("snat", "abc"),      # Неверный IP
    ("invalid", "8.8.8.8"),# Неверный тип
    (None, "8.8.8.8")     # Нет типа, но есть IP
])
def test_validate_nat_invalid(nat_type, nat_ip):
    rule = {**VALID_RULE, "nat_type": nat_type, "nat_ip": nat_ip}
    is_valid, msg = rules._validate_rule(rule, existing_rules=[])
    assert is_valid is False
    assert "NAT" in msg or "IP-адрес" in msg


# ==========================================
# ТЕСТЫ ОПЕРАЦИЙ (CRUD)
# В порядке кодов событий (300 -> 304)
# ==========================================

# --- Код 0 (спец. случай): show_rules ---
@patch('core.rules._load_config')
def test_show_rules_all(mock_load, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.show_rules()
    assert result["status"] == "success"
    assert len(result["data"]) == 1
    assert result["data"][0]["num"] == 10

@patch('core.rules._load_config')
def test_show_rules_specific(mock_load, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.show_rules(num=10)
    assert result["status"] == "success"
    assert result["data"]["num"] == 10
    
    result_missing = rules.show_rules(num=99)
    assert result_missing["status"] == "error"

# --- Код 300: add_rule ---
@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_add_rule_success(mock_load, mock_save, empty_config):
    mock_load.return_value = empty_config
    result = rules.add_rule({"num": 20, "action": "drop"})
    assert result["status"] == "success"
    assert result["code"] == 300
    mock_save.assert_called_once()

@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_add_rule_error(mock_load, mock_save, empty_config):
    mock_load.return_value = empty_config
    result = rules.add_rule({"num": 20, "action": "pass", "src_ip": "999.999.0.1", "out": "port1"})
    assert result["status"] == "error"
    assert result["code"] == 300
    mock_save.assert_not_called()

# --- Код 301: edit_rule ---
@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_edit_rule_success(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.edit_rule(10, {"comment": "New comment"})
    assert result["status"] == "success"
    assert result["code"] == 301
    saved_config = mock_save.call_args[0][0]
    assert saved_config["rules"][0]["comment"] == "New comment"

@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_edit_rule_not_found(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.edit_rule(999, {"comment": "New comment"})
    assert result["status"] == "error"
    assert result["code"] == 301
    mock_save.assert_not_called()

@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_edit_rule_validation_error(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.edit_rule(10, {"dst_port": 99999})
    assert result["status"] == "error"
    assert result["code"] == 301
    mock_save.assert_not_called()

# --- Код 302: delete_rule ---
@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_delete_rule_success(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.delete_rule(10)
    assert result["status"] == "success"
    assert result["code"] == 302
    saved_config = mock_save.call_args[0][0]
    assert len(saved_config["rules"]) == 0

@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_delete_rule_not_found(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.delete_rule(999)
    assert result["status"] == "error"
    assert result["code"] == 302
    mock_save.assert_not_called()

# --- Код 303: renumber_rule ---
@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_renumber_rule_success(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.renumber_rule(10, 20)
    assert result["status"] == "success"
    assert result["code"] == 303
    saved_config = mock_save.call_args[0][0]
    assert saved_config["rules"][0]["num"] == 20

@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_renumber_rule_not_found(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.renumber_rule(999, 20)
    assert result["status"] == "error"
    assert result["code"] == 303

@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_renumber_rule_number_exists(mock_load, mock_save, config_with_rule):
    config_with_rule["rules"].append({"num": 20, "action": "drop"})
    mock_load.return_value = config_with_rule
    result = rules.renumber_rule(10, 20)
    assert result["status"] == "error"
    assert result["code"] == 303

# --- Код 304: toggle_rule ---
@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_toggle_rule_success(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.toggle_rule(10)
    assert result["status"] == "success"
    assert result["code"] == 304
    saved_config = mock_save.call_args[0][0]
    assert saved_config["rules"][0]["active"] is False

@patch('core.rules._save_config')
@patch('core.rules._load_config')
def test_toggle_rule_not_found(mock_load, mock_save, config_with_rule):
    mock_load.return_value = config_with_rule
    result = rules.toggle_rule(999)
    assert result["status"] == "error"
    assert result["code"] == 304