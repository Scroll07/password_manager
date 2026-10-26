from dataclasses import dataclass
import typer


from pas_app.core.api import Api
from pas_app.dependencies import (
    get_keyring_tool,
    get_logger
)
from pas_app.schemas.api import MessageResponse, VaultsDataResponse
from pas_app.schemas.vaults import EncryptedUserVault, VaultData
from pas_app.services.file_utils import (
    get_local_user_vaults_data
)


logger =  get_logger()

@dataclass
class FetchData:
    push_queue: list[EncryptedUserVault]
    pull_queue: list[EncryptedUserVault | VaultData]
    up_to_date: list[EncryptedUserVault]
    server_map: dict[int, VaultData]

async def get_fetch_data() -> FetchData:
    api = Api()
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    
    response = await api.get_vaults()
    if response.status_code != 200:
        if isinstance(response.content, MessageResponse):
            typer.echo(response.content.detail)
        else:
            typer.echo("Wrong server response type")
        raise typer.Exit(code=1)
    else:
        if isinstance(response.content, VaultsDataResponse):
            server_vaults = response.content.vaults
        else:
            typer.echo("Wrong server response type")
            raise typer.Exit(code=1)
    
    local_data = await get_local_user_vaults_data(username=username)
    
    PUSH_QUEUE: list[EncryptedUserVault] = []
    PULL_QUEUE: list[EncryptedUserVault | VaultData] = []
    UP_TO_DATE: list[EncryptedUserVault] = []
    
    
    if local_data is not None:
        for v_info in local_data.unpushed:
            PUSH_QUEUE.append(v_info.vault)
        
        for server_v in server_vaults:
            if server_v.id in local_data.synced: # vault that existing on device 
                local_v = local_data.synced[server_v.id].vault
                if local_v.version < server_v.version:
                    PULL_QUEUE.append(local_v)
                elif local_v.version > server_v.version:
                    PUSH_QUEUE.append(local_v)
                else: # ==
                    UP_TO_DATE.append(local_v)
            else:
                PULL_QUEUE.append(server_v)
                
    else:
        for v in server_vaults:
            PULL_QUEUE.append(v)
    
    
    return FetchData(
        push_queue=PUSH_QUEUE,
        pull_queue=PULL_QUEUE,
        up_to_date=UP_TO_DATE,
        server_map={v.id: v for v in server_vaults}
    )

async def print_fetch_data(fetch_data: FetchData) -> None:
    typer.echo("\nFETCH SUMMARY:\n")

    # [ PULL NEEDED ]
    pull_count = len(fetch_data.pull_queue)
    typer.echo(f"[ PULL NEEDED ] ({pull_count})")
    if pull_count == 0:
        typer.echo("  (none)")
    else:
        for vault in fetch_data.pull_queue:
            assert type(vault.id) == int 
            typer.echo(f"< {vault.name} (v 1.{vault.version}) --> (v 1.{fetch_data.server_map[vault.id].version})")
    typer.echo()

    # [ PUSH NEEDED ]
    push_count = len(fetch_data.push_queue)
    typer.echo(f"[ PUSH NEEDED ] ({push_count})")
    if push_count == 0:
        typer.echo("  (none)")
    else:
        for vault in fetch_data.push_queue:
            if vault.id is not None and fetch_data.server_map[vault.id]:
                typer.echo(f"> {vault.name} (v 1.{fetch_data.server_map[vault.id].version}) --> (v 1.{vault.version})")
            else:
                typer.echo(f"> {vault.name} (v 1.{vault.version}) [NEW]")
    typer.echo()

    # [ UP TO DATE ]
    up_count = len(fetch_data.up_to_date)
    suffix = "vault" if up_count == 1 else "vaults"
    typer.echo(f"[ UP TO DATE ] ({up_count} {suffix})")

    if up_count == 0:
        typer.echo("  (none)")
    else:
        names = [v.name for v in fetch_data.up_to_date]
        max_preview = 5
        if len(names) > max_preview:
            names_preview = ", ".join(names[:max_preview]) + ", ..."
        else:
            names_preview = ", ".join(names)
        typer.echo(f"  {names_preview}")
    
    typer.echo('\n')
        
async def fetch() -> None:
    fetch_data = await get_fetch_data()
    await print_fetch_data(fetch_data=fetch_data)