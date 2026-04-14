Installation:

```
git clone https://github.com/Scroll07/password_manager.git

cd password_manager
./realise.sh

pas add test -u test -p test --note test
```


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
