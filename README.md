Installation:

```
git clone https://github.com/Scroll07/password_manager.git

cd password_manager
./realise.sh

pas api register
pas add test -u test -p test --note test
```

**BASE COMMANDS**
| Command           | Description           | Example                      |
| ----------------- | --------------------- | ---------------------------- |
| pas add           | Добавить запись       | pas add github -u user --gen |
| pas list          | Список записей        | pas list                     |
| pas get           | Показать запись       | pas get git                  |
| pas copy          | Копировать пароль     | pas copy 2                   |
| pas edit          | Изменить запись       | pas edit 1 -p newpass        |
| pas del           | Удалить запись        | pas del github               |
| pas find          | Поиск                 | pas find @gmail              |
| pas reset-session | Сброс сессии          | pas reset-session            |
| pas export        | Экспорт               | pas export backup.json       |
| pas import        | Импорт                | pas import backup.json       |
| pas change-master | Сменить мастер-пароль | pas change-master            |
| pas create-key    | Генератор паролей     | pas create-key -l 32         |
| pas config        | Настройка конфига     | pas config --token           | 


**API COMMANDS**
| Command          | Description                                                | Example          |
| ---------------- | ---------------------------------------------------------- | ---------------- |
| pas api register | Регистрация в API                                          | pas api register |
| pas api login    | Вход в API                                                 | pas api login    |
| pas api upload   | Загрузить backup файла vault в облако/на сервер            | pas api upload   |
| pas api download | Скачать backup файла vault для восстановления на другом ПК | pas api download |
