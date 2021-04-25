import click

from r2sim import core


@click.command()
@click.argument("this_file", type=click.Path())
@click.argument("other_file", type=click.Path())
def show_interface(this_file: str, other_file: str):
    print(f"[*] Analyzing similarity between {this_file} and {other_file}\n")

    this_core = core.CoreFile(this_file)
    other_core = core.CoreFile(other_file)
    this_core.analyze_file()
    other_core.analyze_file()

    this_core.compare_functions(other_core)


show_interface()
