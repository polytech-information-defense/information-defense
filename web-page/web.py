from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

ROWS = [
    "Строка 1", "Строка 2", "Строка 3", "Строка 4", "Строка 5",
    "Строка 6", "Строка 7", "Строка 8", "Строка 9", "Строка 10",
]

# Состояние на сервере: список строк и текущий вид ("list" или "hello")
state = {"rows": ROWS[:], "view": "list"}

PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>Flask App</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="page">
        <div class="stage">

            <div class="left-buttons">
                <a class="menu-button {% if view == 'page1' %}active{% endif %}" href="{{ url_for('set_view', name='page1') }}">Правила</a>
                <a class="menu-button {% if view == 'page2' %}active{% endif %}" href="{{ url_for('set_view', name='page2') }}">События</a>
                <a class="menu-button {% if view == 'page3' %}active{% endif %}" href="{{ url_for('set_view', name='page3') }}">Пакеты</a>
                <a class="menu-button {% if view == 'page4' %}active{% endif %}" href="{{ url_for('set_view', name='page4') }}">Состояния</a>
                <a class="menu-button {% if view == 'page5' %}active{% endif %}" href="{{ url_for('set_view', name='page5') }}">Конфигурация</a>
                <a class="menu-button {% if view == 'page6' %}active{% endif %}" href="{{ url_for('set_view', name='page6') }}">Пользователи</a>
                <a class="menu-button {% if view == 'page7' %}active{% endif %}" href="{{ url_for('set_view', name='page7') }}">Интерфейс</a>
                <a class="menu-button {% if view == 'page8' %}active{% endif %}" href="{{ url_for('set_view', name='page8') }}">Система</a>
                <a class="menu-button {% if view == 'page9' %}active{% endif %}" href="{{ url_for('set_view', name='page9') }}">Целостность</a>
            </div>

            
            <div class="content-area">
                {% if view == 'page2' %}
                    <div class="hello-world">hello world</div>
                {% else %}
                    <div class="scroll-container">
                        {% for row in rows %}
                            <div class="item-block">
                                <span class="item-text">{{ row }}</span>
                                <form method="post" action="{{ url_for('delete_row') }}">
                                    <input type="hidden" name="idx" value="{{ loop.index0 }}">
                                    <button type="submit" class="delete-button">x</button>
                                </form>
                            </div>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>

        </div>
    </div>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(PAGE, rows=state["rows"], view=state["view"])


@app.route("/view/<name>")
def set_view(name):
    if name in ("page1", "page2"):
        state["view"] = name
    return redirect(url_for("index"))


@app.route("/delete", methods=["POST"])
def delete_row():
    idx = int(request.form["idx"])
    if 0 <= idx < len(state["rows"]):
        state["rows"].pop(idx)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(port=5000)