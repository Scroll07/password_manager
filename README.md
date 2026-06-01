Dependencies that will be installed if you don't have them:
- gnome-keyring
- pipx
- uv

Installation:

```
git clone https://github.com/Scroll07/password_manager.git

cd password_manager
./realise.sh

pas api register
pas add test -u test -p test --note test
```

**BASE COMMANDS**
| Command    | Description                          | Example                      |
| ---------- | ------------------------------------ | ---------------------------- |
| pas add    | Add a new entry to the local vault   | pas add github -u user --gen |
| pas list   | Show all saved entries               | pas list                     |
| pas get    | Show an entry by label               | pas get github               |
| pas copy   | Copy a password by entry number      | pas copy 2                   |
| pas edit   | Edit an existing entry               | pas edit 1 -p newpass        |
| pas del    | Delete an entry from the local vault | pas del github               |
| pas find   | Search entries in the vault          | pas find @gmail              |
| pas export | Export vault data to a file          | pas export backup.json       |
| pas import | Import vault data from a file        | pas import backup.json       |
| pas key    | Generate a password                  | pas key -l 32                |


**API COMMANDS**
| Command                 | Description                                      | Example                 |
| ----------------------- | ------------------------------------------------ | ----------------------- |
| pas api register        | Register a new account for remote backup storage | pas api register        |
| pas api login           | Authenticate and save API session locally        | pas api login           |
| pas api upload          | Upload the current local vault as a backup       | pas api upload          |
| pas api backups         | Interactively manage backups on the server       | pas api backups         |
| pas api change-password | Change the current account password              | pas api change-password |

**USER COMMANDS**
| Command                 | Description                | Example                |
| ------------------------| -------------------------- | ---------------------- |
| pas user delete         | Delete a local user        | pas user delete        |
| pas user change-master  | Change the master password | pas user change-master |

**CONFIG COMMANDS**
| Command                  | Description                     | Example                  |
| ------------------------ | ------------------------------- | ------------------------ |
| pas config user          | Set the default local user      | pas config user          |
| pas config url           | View or change the API base URL | pas config url           |
| pas config token         | View or change the bot token    | pas config token         |
| pas config reset-session | Reset the current local session | pas config reset-session |
