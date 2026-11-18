import pytest
from unittest.mock import patch
from cli.main import main

# ==========================================
# ФИКСТУРЫ
# ==========================================

@pytest.fixture
def sample_rule():
    """Тестовое правило для имитации ответа от ядра."""
    return {
        "num": 10, "action": "pass", "in": "port1", "src_mac": "any", "dst_mac": "any",
        "src_ip": "192.168.1.0/24", "dst_ip": "any", "proto": "tcp", "src_port": "any",
        "dst_port": 80, "icmp_type": "any", "icmp_code": "any", "out": "port2", "jump": None,
        "stateful": True, "active": True, "log": False, "comment": "Test rule",
        "nat_type": None, "nat_ip": None
    }

# ==========================================
# ТЕСТЫ КОМАНДЫ SHOW (Просмотр)
# ==========================================

@patch('sys.argv', ['main.py', 'rule', 'show'])
@patch('core.rules.show_rules')
def test_cli_show_all(mock_show, capsys, sample_rule):
    """Тест вывода всех правил (список)."""
    mock_show.return_value = [sample_rule] # Ядро вернуло список
    
    main() # Запускаем CLI
    
    captured = capsys.readouterr()
    # Проверяем, что вывод красиво отформатирован
    assert "[ИНФО] Всего правил в системе: 1" in captured.out
    assert "[ ПРАВИЛО №10 ]" in captured.out
    assert "Действие : pass" in captured.out

@patch('sys.argv', ['main.py', 'rule', 'show', '--num', '10'])
@patch('core.rules.show_rules')
def test_cli_show_single(mock_show, capsys, sample_rule):
    """Тест вывода одного правила (словарь)."""
    mock_show.return_value = sample_rule # Ядро вернуло словарь
    
    main()
    
    captured = capsys.readouterr()
    assert "[ ПРАВИЛО №10 ]" in captured.out
    assert "Действие : pass" in captured.out

@patch('sys.argv', ['main.py', 'rule', 'show', '--num', '99'])
@patch('core.rules.show_rules')
def test_cli_show_not_found(mock_show, capsys):
    """Тест вывода, если правило не найдено."""
    mock_show.return_value = None # Ядро вернуло None
    
    main()
    
    captured = capsys.readouterr()
    assert "[ИНФО] Правило с номером 99 не найдено." in captured.out

# ==========================================
# ТЕСТЫ КОМАНДЫ ADD (Добавление)
# ==========================================

@patch('sys.argv', ['main.py', 'rule', 'add', '--num', '20', '--action', 'drop', '--src-ip', '1.1.1.1'])
@patch('core.rules.add_rule')
def test_cli_add_success(mock_add, capsys):
    """Тест успешного добавления правила."""
    mock_add.return_value = {"status": "success", "code": 300, "description": "Добавление правила"}
    
    main()
    
    captured = capsys.readouterr()
    assert "[УСПЕХ] Код: 300 | Описание: Добавление правила" in captured.out
    
    # Проверяем, что CLI правильно передал аргументы в ядро
    args_passed = mock_add.call_args[0][0]
    assert args_passed['num'] == 20
    assert args_passed['action'] == 'drop'
    assert args_passed['src_ip'] == '1.1.1.1'
    # Проверяем, что служебные поля argparse не попали в ядро
    assert 'action_cmd' not in args_passed
    assert 'command' not in args_passed

@patch('sys.argv', ['main.py', 'rule', 'add', '--num', '20', '--action', 'drop'])
@patch('core.rules.add_rule')
def test_cli_add_error(mock_add, capsys):
    """Тест вывода ошибки при добавлении."""
    mock_add.return_value = {
        "status": "error", "code": 300, "description": "Добавление правила", "reason": "Ошибка валидации"
    }
    
    main()
    
    captured = capsys.readouterr()
    assert "[ОШИБКА] Код: 300 | Описание: Добавление правила | Причина: Ошибка валидации" in captured.out

# ==========================================
# ТЕСТЫ ОСТАЛЬНЫХ КОМАНД (Edit, Delete, Renumber, Toggle)
# ==========================================

@patch('sys.argv', ['main.py', 'rule', 'edit', '--num', '10', '--src-ip', '2.2.2.2'])
@patch('core.rules.edit_rule')
def test_cli_edit(mock_edit, capsys):
    """Тест изменения правила."""
    mock_edit.return_value = {"status": "success", "code": 301, "description": "Изменение правила"}
    
    main()
    
    captured = capsys.readouterr()
    assert "[УСПЕХ] Код: 301" in captured.out
    
    # Проверяем передачу аргументов
    args, kwargs = mock_edit.call_args
    assert kwargs['num'] == 10
    assert kwargs['update_data']['src_ip'] == '2.2.2.2'
    assert 'action_cmd' not in kwargs['update_data']

@patch('sys.argv', ['main.py', 'rule', 'delete', '--num', '10'])
@patch('core.rules.delete_rule')
def test_cli_delete(mock_del, capsys):
    """Тест удаления правила."""
    mock_del.return_value = {"status": "success", "code": 302, "description": "Удаление правила"}
    
    main()
    
    captured = capsys.readouterr()
    assert "[УСПЕХ] Код: 302" in captured.out
    mock_del.assert_called_once_with(num=10)

@patch('sys.argv', ['main.py', 'rule', 'renumber', '--old', '10', '--new', '20'])
@patch('core.rules.renumber_rule')
def test_cli_renumber(mock_renumber, capsys):
    """Тест перенумерации правила."""
    mock_renumber.return_value = {"status": "success", "code": 303, "description": "Перенумерация правил"}
    
    main()
    
    captured = capsys.readouterr()
    assert "[УСПЕХ] Код: 303" in captured.out
    mock_renumber.assert_called_once_with(old_num=10, new_num=20)

@patch('sys.argv', ['main.py', 'rule', 'toggle', '--num', '10'])
@patch('core.rules.toggle_rule')
def test_cli_toggle(mock_toggle, capsys):
    """Тест активации/деактивации правила."""
    mock_toggle.return_value = {"status": "success", "code": 304, "description": "Правило деактивировано"}
    
    main()
    
    captured = capsys.readouterr()
    assert "[УСПЕХ] Код: 304" in captured.out
    mock_toggle.assert_called_once_with(num=10)