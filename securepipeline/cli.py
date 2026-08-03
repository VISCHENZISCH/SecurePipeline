import sys
import click

from securepipeline import __version__
from securepipeline.core.detector import detect_stacks
from securepipeline.core.orchestrator import run_scan


@click.group()
@click.version_option(version=__version__, prog_name="securepipeline")
def cli():
    """SecurePipeline - Scanner de sécurité multi-stack."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--format", "output_format", type=click.Choice(["md", "html"]), default="md")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default="critical")
@click.option("--interactive/--headless", default=True, help="Mode TUI ou mode CI headless")
def scan(path, output_format, fail_on, interactive):
    """Lance un scan de sécurité sur PATH."""
    stacks = detect_stacks(path)
    if not stacks:
        click.echo("Aucune stack détectée.")
        sys.exit(1)

    click.echo(f"Stacks détectées : {', '.join(stacks)}")

    if interactive:
        from securepipeline.ui.app import SecurePipelineApp
        SecurePipelineApp(path=path, stacks=stacks).run()
    else:
        result = run_scan(path, stacks)
        exit_code = result.exit_code(fail_on=fail_on)
        sys.exit(exit_code)


def main():
    """__main__.py"""
    cli()


if __name__ == "__main__":
    main()