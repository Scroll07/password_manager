#!/bin/bash

# 1. Удали через pipx
pipx uninstall password-manager

# 2. Удали вручную symlink
rm -f ~/.local/bin/pas

# 3. Удали старое окружение pipx
rm -rf ~/.local/share/pipx/venvs/password-manager
rm -rf ~/.local/share/pipx/venvs/pas

# 4. Теперь ставь wheel
pipx install dist/password_manager-*.whl