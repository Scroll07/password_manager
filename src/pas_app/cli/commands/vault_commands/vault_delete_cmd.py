

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from tabulate import tabulate
import typer

from pas_app.adapters.console import clear_console
from pas_app.cli.commands.vault_commands.vault_multi import check_status_unlock_vault
from pas_app.core.api import Api
from pas_app.dependencies import (
    get_logger,
    get_keyring_tool,
)
from pas_app.schemas.api import DeleteVaultResponse, MessageResponse, VaultsDataResponse
from pas_app.schemas.vaults import LocalVaultInfo, VaultData, LocalVaultsData 
from pas_app.services.file_utils import (
    get_local_user_vaults_data,
    
)


@dataclass
class UnifiedVault:
    name: str
    server: VaultData | None = None
    local: LocalVaultInfo | None = None

    @property
    def location_label(self) -> str:
        if self.server and self.local:
            return "Local & Remote"
        elif self.server:
            return "Remote only"
        elif self.local:
            return "Local only"
        return "Unknown"

    @property
    def created_at_display(self) -> str:
        if self.server and getattr(self.server, "created_at", None):
            created = self.server.created_at_formatted
            return created
        return "-"


def build_unified_vaults(
    local_vaults: LocalVaultsData | None,
    server_vaults: list[VaultData]
) -> list[UnifiedVault]:
    unified: list[UnifiedVault] = []
    synced_map = local_vaults.synced if local_vaults else {}
    used_ids = []
    
    for s_v in server_vaults:
        local_info = synced_map.get(s_v.id)
        if local_info:
            used_ids.append(s_v.id)
        unified.append(
            UnifiedVault(
                name=s_v.name,
                server=s_v,
                local=local_info
            )
        )
    
    if local_vaults:
        for l_v in local_vaults.unpushed:
            unified.append(
                UnifiedVault(
                    name=l_v.vault.name,
                    server=None,
                    local=l_v
                )
            )
            
    return unified
    
def print_and_choose_vault_to_delete(vaults: list[UnifiedVault]) -> UnifiedVault | None:
    table_data = [
        [i, v.name, v.location_label, v.created_at_display]
        for i, v in enumerate(vaults, start=1)
    ]
    
    headers = ["#", "Name", "Location", "Created At"]

    while True:
        clear_console()
        typer.echo("\nSelect vault to delete:")
        typer.echo(tabulate(table_data, headers=headers, tablefmt="simple"))
        choice = typer.prompt("Choose vault #", default="0").strip()
        if not choice.isdigit():
            typer.echo("Please enter a valid number.")
            continue
        idx = int(choice)
        if idx == 0:
            return None
        if 1 <= idx <= len(vaults):
            return vaults[idx - 1]
        typer.echo(f"Number must be between 1 and {len(vaults)}.")


AVAILABLE_ACTIONS = Literal['remote', 'local', 'both', 'cancel']

def choose_delete_action(vault: UnifiedVault) -> AVAILABLE_ACTIONS:
    available_actions: dict[str, tuple[str, AVAILABLE_ACTIONS]] = {}

    if vault.local:
        available_actions["1"] = ("Delete Locally", "local")
    if vault.server:
        available_actions["2"] = ("Delete Remote", "remote")
    if vault.local and vault.server:
        available_actions["3"] = ("Delete Remote + Locally", "both")

    while True:
        clear_console()
        typer.echo(f"\nTarget: '{vault.name}' ({vault.location_label})")
        typer.echo("Available actions:")
        
        for key in sorted(available_actions.keys()):
            label, _ = available_actions[key]
            typer.echo(f"  [{key}] {label}")
        typer.echo("  [0] Cancel")

        choice = typer.prompt("\nSelect action", default="0").strip()
        
        if choice == "0":
            return "cancel"
        if choice in available_actions:
            return available_actions[choice][1]

        typer.echo("Invalid choice for this vault.")
        typer.prompt("Press Enter to continue...", default="", show_default=False)

logger = get_logger()

async def delete_vault():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    
    # получить локальные и серверные vaults
    
    # отрисовать в виде 
    # [№]   Name    Location        created_at
    #  1     Vault Local | Remote      date

    # пользователь выбирает один из них
    # выбор действий:
    # [1] Delete Localy
    # [2] Delete Remote                
    # [3] Delete Remote + Localy                
    # [0] Cancel       
    
    # соответственно добавить функции под эти действия
             
    api = Api()
    
    async def delete_online(vault: VaultData):
        logger.info(f"Initiating deletion for vault {vault.id} ('{vault.name}')")
        await check_status_unlock_vault(vault=vault)

        api = Api()

        response = await api.delete_vault(vault_id=vault.id)
        if response.status_code != 200:
            if type(response.content) != DeleteVaultResponse:
                if isinstance(response.content, MessageResponse):
                    typer.echo(response.content.detail)
                else:
                    typer.echo("Wrong server response type")
                raise typer.Exit(code=1)

    def delete_offline(vault_path: Path):
        if not vault_path.exists() or not vault_path.is_file():
            typer.echo("Vault file does not exist")
            raise typer.Exit(code=1)
        vault_path.unlink()
        typer.echo("Vault file was successfully removed")
        
        
    while True:
        response = await api.get_vaults()
        if type(response.content) != VaultsDataResponse:
            if isinstance(response.content, MessageResponse):
                typer.echo(response.content.detail)
            else:
                typer.echo("Wrong server response type")
            raise typer.Exit(code=1)
        
        assert response.status_code == 200
        
        server_vaults = response.content.vaults
        local_vaults = await get_local_user_vaults_data(username=username)
        
        vaults = build_unified_vaults(local_vaults=local_vaults, server_vaults=server_vaults)
        if not vaults:
            typer.echo("You have no vaults to delete.")
            raise typer.Exit(code=0)

        chosen_vault = print_and_choose_vault_to_delete(vaults=vaults)
        if chosen_vault is None:
            typer.echo("Cancelled.")
            raise typer.Exit(code=0)

        action = choose_delete_action(vault=chosen_vault)
        if action == "cancel":
            typer.echo("Cancelled.")
            await asyncio.sleep(1)
            continue
        
        
        confirm = typer.confirm(
            f"Are you sure you want to delete '{chosen_vault.name}' ({action})?",
            default=False
        )
        if not confirm:
            typer.echo("Operation aborted.")
            await asyncio.sleep(2)
            continue

        if action == "local":
            if chosen_vault.local:
                delete_offline(chosen_vault.local.path)
        elif action == "remote":
            if chosen_vault.server:
                await delete_online(chosen_vault.server)
        elif action == "both":
            if chosen_vault.server:
                await delete_online(chosen_vault.server)
            if chosen_vault.local:
                delete_offline(chosen_vault.local.path)
