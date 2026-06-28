import typer
from tabulate import tabulate

from pas_app.core.api import Api
from pas_app.core.logger import get_logger
from pas_app.schemas.api import MessageResponse, BackupStatsResponse, BackupStats
from pas_app.config import get_config

logger = get_logger()

async def backups_stats():
    config = get_config()
    config_data = config._refresh()
    api = Api()

    logger.info(f"Backup stats request for user: {config_data.local.default_user}")
    response = await api.stats_backup()
    logger.info(f"Backup stats response status: {response.status_code}")

    if not isinstance(response.content, BackupStatsResponse):
        if isinstance(response.content, MessageResponse):
            logger.error(f"Backup stats failed for user {config_data.local.default_user}: {response.content.detail}")
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        logger.error(f"Wrong content from api for user {config_data.local.default_user}: {type(response.content)}")
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)

    stats = BackupStats.model_validate(response.content.stats)
    logger.info(f"Backup stats successful for user: {config_data.local.default_user}")
    print_stats(stats=stats)
    
    
def print_stats(stats: BackupStats) -> None:
    headers = ["Metrics", "Value"]
    metrics = ["Backups count", "MAX rows", "MIN rows", "AVG rows", "Backups count for week"]
    rows = []
    for m, v in zip(metrics, stats.model_dump().values()):
        rows.append([m, v])
    
    typer.echo("\nStatistic of Backups:")
    typer.echo(tabulate(rows, headers=headers, tablefmt="simple_grid"))
    
    