# Ремонтная мастерская

Учебный проект: сайт для приёма заявок на ремонт техники, отслеживания статуса и учёта запчастей.
Стек: Python, Flask, SQLite, HTML, CSS, JavaScript.

## Запуск

    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    python app.py

Сайт: http://127.0.0.1:5000

## Тесты

    python -m unittest tests -v

## Тестовые учётные записи

| Роль | E-mail | Пароль |
|---|---|---|
| Администратор | admin@shop.ru | admin123 |
| Мастер | master@shop.ru | master123 |
| Клиент | client@shop.ru | client123 |
