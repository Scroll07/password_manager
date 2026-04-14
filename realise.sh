#!/bin/bash

pipx uninstall password-manager

uv run python -m build --wheel

pipx install dist/password_manager-*.whl