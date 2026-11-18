import argparse
import sys
import os

# Добавляем корень проекта в sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import rules

def print_action_result(result: dict):
    """
    Вывод результата для команд, изменяющих систему (add, edit, delete, renumber, toggle).
    Обязательно выводит код события и статус.
    """
    if result.get("status") == "success":
        print(f"[УСПЕХ] Код: {result['code']} | Описание: {result['description']}")
    else:
        print(f"[ОШИБКА] Код: {result.get('code', 'N/A')} | Описание: {result.get('description', 'Ошибка')} | Причина: {result.get('reason')}")

def print_rules_table(rules_list: list):
    """
    Вывод списка правил в виде блочной структуры.
    Масштабируется до любого количества правил (100, 1000).
    Содержит 100% полей.
    """
    if not rules_list:
        print("[ИНФО] Список правил пуст.")
        return

    print(f"[ИНФО] Всего правил в системе: {len(rules_list)}")
    print("=" * 80)

    for r in rules_list:
        # Форматируем пустые значения (None) в прочерки для красоты
        def fmt(val):
            return str(val) if val not in [None, ""] else "-"

        # Строка 1: Номер, действие и протокол
        print(f" [ ПРАВИЛО №{r.get('num')} ]")
        print(f"  Действие : {fmt(r.get('action'))}")
        print(f"  Протокол : {fmt(r.get('proto'))}")
        
        # Строка 2: Интерфейсы
        print(f"  Интерфейсы: In: {fmt(r.get('in'))} | Out: {fmt(r.get('out'))} | Jump: {fmt(r.get('jump'))}")
        
        # Строка 3: Адресация
        print(f"  IP-адреса : {fmt(r.get('src_ip'))} -> {fmt(r.get('dst_ip'))}")
        print(f"  MAC-адреса: {fmt(r.get('src_mac'))} -> {fmt(r.get('dst_mac'))}")
        
        # Строка 4: Порты и ICMP
        print(f"  Порты     : {fmt(r.get('src_port'))} -> {fmt(r.get('dst_port'))}")
        print(f"  ICMP      : Type: {fmt(r.get('icmp_type'))} | Code: {fmt(r.get('icmp_code'))}")
        
        # Строка 5: NAT
        if r.get("nat_type"):
            print(f"  NAT       : {r.get('nat_type')} на {fmt(r.get('nat_ip'))}")
            
        # Строка 6: Флаги
        print(f"  Флаги     : stateful={r.get('stateful')} | active={r.get('active')} | log={r.get('log')}")
        
        # Строка 7: Комментарий
        print(f"  Комментарий: {fmt(r.get('comment'))}")
        print("-" * 80)

def main():
    parser = argparse.ArgumentParser(description="CLI управления межсетевым экраном")
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")

    # --- Группа rule ---
    rule_parser = subparsers.add_parser("rule", help="Управление правилами")
    rule_subparsers = rule_parser.add_subparsers(dest="action_cmd", help="Действия")

    # --- rule show ---
    show_parser = rule_subparsers.add_parser("show", help="Просмотр правил")
    show_parser.add_argument("--num", type=int, help="Номер правила")

    # --- rule add ---
    add_parser = rule_subparsers.add_parser("add", help="Добавление правила")
    # Обязательные
    add_parser.add_argument("--num", type=int, required=True, help="Номер правила")
    add_parser.add_argument("--action", choices=["pass", "drop", "jump"], required=True, help="Действие")
    # Необязательные (порядок не важен)
    add_parser.add_argument("--in", dest="in_iface", help="Входной интерфейс")
    add_parser.add_argument("--src-mac", help="MAC источника")
    add_parser.add_argument("--dst-mac", help="MAC приемника")
    add_parser.add_argument("--src-ip", help="IP источника")
    add_parser.add_argument("--dst-ip", help="IP приемника")
    add_parser.add_argument("--proto", help="Протокол")
    add_parser.add_argument("--src-port", help="Порт источника")
    add_parser.add_argument("--dst-port", help="Порт приемника")
    add_parser.add_argument("--icmp-type", type=int, help="Тип ICMP")
    add_parser.add_argument("--icmp-code", type=int, help="Код ICMP")
    add_parser.add_argument("--out", help="Выходной интерфейс")
    add_parser.add_argument("--jump", type=int, help="Номер перехода")
    # Используем lambda для преобразования строк "true"/"false" в Python bool
    add_parser.add_argument("--stateful", type=lambda x: str(x).lower() == 'true', help="Контроль состояния (true/false)")
    add_parser.add_argument("--active", type=lambda x: str(x).lower() == 'true', help="Активность (true/false)")
    add_parser.add_argument("--log", type=lambda x: str(x).lower() == 'true', help="Логирование (true/false)")
    add_parser.add_argument("--comment", help="Комментарий")
    add_parser.add_argument("--nat-type", choices=["snat", "dnat"], help="Тип NAT")
    add_parser.add_argument("--nat-ip", help="IP для NAT")

    # --- rule edit ---
    edit_parser = rule_subparsers.add_parser("edit", help="Изменение правила")
    edit_parser.add_argument("--num", type=int, required=True, help="Номер правила")
    edit_parser.add_argument("--action", choices=["pass", "drop", "jump"], help="Действие")
    edit_parser.add_argument("--in", dest="in_iface", help="Входной интерфейс")
    edit_parser.add_argument("--src-mac", help="MAC источника")
    edit_parser.add_argument("--dst-mac", help="MAC приемника")
    edit_parser.add_argument("--src-ip", help="IP источника")
    edit_parser.add_argument("--dst-ip", help="IP приемника")
    edit_parser.add_argument("--proto", help="Протокол")
    edit_parser.add_argument("--src-port", help="Порт источника")
    edit_parser.add_argument("--dst-port", help="Порт приемника")
    edit_parser.add_argument("--icmp-type", type=int, help="Тип ICMP")
    edit_parser.add_argument("--icmp-code", type=int, help="Код ICMP")
    edit_parser.add_argument("--out", help="Выходной интерфейс")
    edit_parser.add_argument("--jump", type=int, help="Номер перехода")
    edit_parser.add_argument("--stateful", type=lambda x: str(x).lower() == 'true', help="Контроль состояния")
    edit_parser.add_argument("--active", type=lambda x: str(x).lower() == 'true', help="Активность")
    edit_parser.add_argument("--log", type=lambda x: str(x).lower() == 'true', help="Логирование")
    edit_parser.add_argument("--comment", help="Комментарий")
    edit_parser.add_argument("--nat-type", choices=["snat", "dnat"], help="Тип NAT")
    edit_parser.add_argument("--nat-ip", help="IP для NAT")

    # --- rule delete ---
    delete_parser = rule_subparsers.add_parser("delete", help="Удаление правила")
    delete_parser.add_argument("--num", type=int, required=True, help="Номер правила")

    # --- rule renumber ---
    renumber_parser = rule_subparsers.add_parser("renumber", help="Перенумерация правила")
    renumber_parser.add_argument("--old", type=int, required=True, help="Старый номер")
    renumber_parser.add_argument("--new", type=int, required=True, help="Новый номер")

    # --- rule toggle ---
    toggle_parser = rule_subparsers.add_parser("toggle", help="Активация/деактивация")
    toggle_parser.add_argument("--num", type=int, required=True, help="Номер правила")

    # --- Парсинг ---
    args = parser.parse_args()

    if args.command == "rule":
        if args.action_cmd == "show":
            data = rules.show_rules(num=args.num)
            if data is None:
                print(f"[ИНФО] Правило с номером {args.num} не найдено.")
            elif isinstance(data, list):
                print_rules_table(data)
            elif isinstance(data, dict):
                print_rules_table([data])

        elif args.action_cmd == "add":
            # Собираем словарь, исключая служебные поля и None
            rule_data = {k: v for k, v in vars(args).items() 
                         if v is not None and k not in ["command", "action_cmd"]}
            if "in_iface" in rule_data:
                rule_data["in"] = rule_data.pop("in_iface")
            
            result = rules.add_rule(rule_data)
            print_action_result(result)

        elif args.action_cmd == "edit":
            update_data = {k: v for k, v in vars(args).items() 
                           if v is not None and k not in ["command", "action_cmd", "num"]}
            if "in_iface" in update_data:
                update_data["in"] = update_data.pop("in_iface")
            
            result = rules.edit_rule(num=args.num, update_data=update_data)
            print_action_result(result)

        elif args.action_cmd == "delete":
            result = rules.delete_rule(num=args.num)
            print_action_result(result)

        elif args.action_cmd == "renumber":
            result = rules.renumber_rule(old_num=args.old, new_num=args.new)
            print_action_result(result)

        elif args.action_cmd == "toggle":
            result = rules.toggle_rule(num=args.num)
            print_action_result(result)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()