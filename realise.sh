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

function check_installed() {
    app="$1"
    if command -v "$app" 1>/dev/null 2>&1; then
        echo "$app was found"
        return 0
    fi
    return 1
}


function ask_install() {
    name="$1"
    pck_mgr="$2"

    echo "Do you want to install $name? [y/n]"
    read choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        #скачать &name не знаю команду как качивать правильно
    else
        echo "Canselled to install $name"
    fi
    
}


function define_packpage_manager() {
    if check_installed pacman; then
        echo "pacman"
    elif check_installed apt; then
        echo "apt"
    else
        echo "none"
    fi   
    return 0
}



function install_dependencies () {
    pck_mgr="$1"
    if ! check_keyring_installed; then
        ask_install #мой keyring я не помню просто $pck_mgr
    fi
    if ! check_installed pipx; then
        ask_install pipx $pck_mgr
    fi
    if ! check_installed uv; then
        ask_install uv $pck_mgr
    fi
}


function main() {
    pck_mgr = define_packpage_manager
    if [ "$pck_mgr" = "no manager" ]; then
        #закончить скрипт
    fi

    install_dependencies $pck_mgr


    pipx uninstall password-manager

    uv run python -m build --wheel

    pipx install dist/password_manager-*.whl
}