#!/bin/bash



function check_keyring_installed() {
    if command -v gnome-keyring-daemon 1>/dev/null 2>&1; then
        echo "Gnome keyring was found"
        return 0
    elif command -v secret-tool 1>/dev/null 2>&1; then
        echo "Secret-tool was found"
        return 0
    elif (command -v kwalletd5 >/dev/null 2>&1) || (command -v kwalletd 1>/dev/null 2>&1); then
        echo "Kwalletd was found"
        return 0
    fi

    return 1
}

function check_installed_quite() {
    local app="$1"
    if command -v "$app" 1>/dev/null 2>&1; then
        return 0
    fi
    return 1
}

function check_installed() {
    local app="$1"
    if check_installed_quite "$app"; then
        echo "$app was found"
        return 0
    fi
    return 1
}

function apt_install() {
    local name="$1"

    sudo apt install "$name"
}

function pacman_install() {
    local name="$1"

    sudo pacman -S "$name"
}


function ask_install() {
    local name="$1"
    local pck_mgr="$2"

    echo "Do you want to install $name? [y/n]"
    read choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        if [ "$pck_mgr" = "pacman" ]; then
            pacman_install "$name"
        elif [ "$pck_mgr" = "apt" ]; then
            apt_install "$name"
        fi
    else
        echo "Canselled to install $name"
    fi
    
}


function define_packpage_manager() {
    if check_installed_quite pacman; then
        echo "pacman"
    elif check_installed_quite apt; then
        echo "apt"
    else
        echo "none"
    fi   
    return 0
}



function install_dependencies () {
    local pck_mgr="$1"
    if ! check_keyring_installed; then
        ask_install gnome-keyring "$pck_mgr"
    fi
    if ! check_installed pipx; then
        ask_install pipx "$pck_mgr"
    fi
    if ! check_installed uv; then
        ask_install uv "$pck_mgr"
    fi
}

function delete_old_builds () {
    local DIR="$1"

    rm -rf "${DIR}/build/"
    rm -rf "${DIR}/dist/"

    echo "${DIR}/build/ was deleted"
    echo "${DIR}/dist/ was deleted"
    
    return 0
}

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "$DIR"

function main() {
    local pck_mgr=$(define_packpage_manager)

    if [ "$pck_mgr" = "none" ]; then
        echo "Supported package manager was not found"
        exit 1
    fi

    install_dependencies "$pck_mgr"

    pipx uninstall password-manager

    delete_old_builds "$DIR"

    uv run python -m build --wheel

    pipx install dist/password_manager-*.whl
}

main