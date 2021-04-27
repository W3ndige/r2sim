import click
import logging

from pathlib import Path
from typing import List, Optional

from r2sim import core

logger = logging.getLogger("r2sim")


@click.command()
@click.argument("filename_1", type=click.Path())
@click.argument("filename_2", type=click.Path())
@click.option("-d", "--diff", "diff", is_flag=True)
def main_interface(filename_1: str, filename_2: str, diff: bool):

    logging.basicConfig(level=logging.INFO)

    path_1 = Path(filename_1)
    path_2 = Path(filename_2)

    core_1 = core.CoreFile(path_1)
    core_2 = core.CoreFile(path_2)

    core_1.analyze_file()
    core_2.analyze_file()

    core_1.compare_functions(core_2, diff)
