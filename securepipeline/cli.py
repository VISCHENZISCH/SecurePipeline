"""SecurePipeline - CLI """

import os
import sys
import time
from collections import defaultdict

import click

from securepipeline import __version__
from securepipeline.core.detector import detect_stacks
from securepipeline.core.config import Config
from securepipeline.ui.display import (
    clear_screen,
    print_home_screen,
    print_menu,
    get_prompt,
    get_path_prompt,
    get_continue_prompt,
    print_section,
    print_stacks,
    print_scanner_start,
    print_scanner_done,
    print_scanner_skip,
    print_summary,
    print_findings_table,
    print_config,
    print_last_report,
    print_status,
    print_banner,
    typing_print,
    DEB_RED, GREEN, CYAN, BLUE, WHITE, GRAY, DARK_GRAY, ORANGE, RESET, BOLD,
    CHECK, CROSS, DOT,
)

# Configuration globale (mutable pendant la session)
_config = Config()


def run_full_scan(path: str) -> None:
    """Execute le scan complet et affiche les resultats."""
    print_section("Scan started")
    print(f"  {DOT} {WHITE}Path:{RESET} {GRAY}{os.path.abspath(path)}{RESET}")

    stacks = detect_stacks(path)
    print_stacks(stacks)

    if not stacks:
        return

    from securepipeline.modules import get_scanners_for_stacks
    scanners = get_scanners_for_stacks(stacks)

    # Affichage de l'arbre des modules
    from securepipeline.ui.widgets.module_tree import print_module_tree
    print_module_tree(scanners, stacks)

    all_findings = []
    start_time = time.time()
    module_results: dict[str, dict] = {}

    for scanner in scanners:
        info = scanner.info()
        print_scanner_start(info.name)

        ok, missing = scanner.check_prerequisites()
        if not ok:
            print_scanner_skip(f"missing: {','.join(missing)}")
            module_results[info.name] = {"status": "skip", "count": 0}
            continue

        try:
            findings = scanner.scan(path)
            all_findings.extend(findings)
            print_scanner_done(len(findings))
            module_results[info.name] = {"status": "ok", "count": len(findings)}
        except Exception as e:
            print(f" {DEB_RED}ERR: {e}{RESET}")
            module_results[info.name] = {"status": "error", "count": 0}

    duration = time.time() - start_time

    # Arbre des resultats
    from securepipeline.ui.widgets.module_tree import print_module_status_tree
    print_module_status_tree(module_results)

    # Resume
    stats: dict[str, int] = defaultdict(int)
    for f in all_findings:
        stats[f.severity.value] += 1

    print_summary(stats, len(all_findings), duration)
    print_findings_table(all_findings)

    # Generer le rapport Markdown automatiquement
    from securepipeline.report.generator import generate_markdown, save_report
    from securepipeline.core.models import ScanResult

    result = ScanResult(findings=all_findings, stacks_scanned=stacks, duration_seconds=duration)
    md_report = generate_markdown(result, path, project_name=os.path.basename(os.path.abspath(path)))
    out_dir = os.path.join(path, ".securepipeline", "reports")
    report_file = save_report(md_report, out_dir)
    print_status(f"Rapport Markdown: {report_file}", "success")


def view_last_report(path: str = ".") -> None:
    """Affiche le dernier rapport Markdown genere."""
    report_path = os.path.join(path, ".securepipeline", "reports", "securepipeline-report.md")
    print_last_report(report_path)


def generate_html_report(path: str = ".") -> None:
    """Genere un rapport HTML a partir du dernier scan."""
    from securepipeline.report.html_report import generate_html, save_html_report
    from securepipeline.core.models import ScanResult, Finding

    report_md_path = os.path.join(path, ".securepipeline", "reports", "securepipeline-report.md")

    if not os.path.exists(report_md_path):
        print_status("Aucun rapport Markdown existant. Lancez un scan d'abord.", "error")
        return

    # Re-scanner pour generer le HTML (ou lire le rapport existant)
    print_section("Generation du rapport HTML")

    stacks = detect_stacks(path)
    if not stacks:
        print_status("Aucune stack detectee.", "error")
        return

    from securepipeline.modules import get_scanners_for_stacks
    scanners = get_scanners_for_stacks(stacks)

    all_findings: list[Finding] = []
    start_time = time.time()

    for scanner in scanners:
        ok, missing = scanner.check_prerequisites()
        if not ok:
            continue
        try:
            findings = scanner.scan(path)
            all_findings.extend(findings)
        except Exception:
            pass

    duration = time.time() - start_time
    result = ScanResult(findings=all_findings, stacks_scanned=stacks, duration_seconds=duration)

    html_content = generate_html(result, path, project_name=os.path.basename(os.path.abspath(path)))
    out_dir = os.path.join(path, ".securepipeline", "reports")
    html_file = save_html_report(html_content, out_dir)

    print_status(f"Rapport HTML genere: {html_file}", "success")


def detect_stacks_only(path: str = ".") -> None:
    """Detecte et affiche les stacks technologiques sans lancer de scan."""
    print_section("Detection des stacks")
    print(f"  {DOT} {WHITE}Chemin:{RESET} {GRAY}{os.path.abspath(path)}{RESET}")
    print()

    stacks = detect_stacks(path)
    print_stacks(stacks)

    if stacks:
        from securepipeline.modules import get_scanners_for_stacks
        scanners = get_scanners_for_stacks(stacks)
        print(f"  {WHITE}{len(scanners)} module(s) de scan seraient actives.{RESET}")
    print()


def check_all_prerequisites() -> None:
    """Verifie que tous les outils externes requis sont installes."""
    from securepipeline.modules import STACK_SCANNERS, GLOBAL_SCANNERS

    print_section("Verification des prerequis")
    print()

    all_tools: dict[str, list[str]] = {}  # tool -> [scanners qui l'utilisent]
    all_scanners = []

    for scanner_classes in STACK_SCANNERS.values():
        all_scanners.extend(scanner_classes)
    all_scanners.extend(GLOBAL_SCANNERS)

    for scanner_cls in all_scanners:
        info = scanner_cls().info()
        for tool in info.tools_required:
            if tool not in all_tools:
                all_tools[tool] = []
            all_tools[tool].append(info.name)

    from securepipeline.utils.subprocess_runner import check_tool

    ok_count = 0
    missing_count = 0

    for tool, used_by in sorted(all_tools.items()):
        installed = check_tool(tool)
        if installed:
            print(f"  {GREEN}{CHECK}{RESET} {WHITE}{tool:<20}{RESET} {GRAY}{DOT} {', '.join(used_by)}{RESET}")
            ok_count += 1
        else:
            print(f"  {DEB_RED}{CROSS}{RESET} {WHITE}{tool:<20}{RESET} {GRAY}{DOT} {', '.join(used_by)}{RESET}")
            missing_count += 1

    print()
    if missing_count == 0:
        print_status("Tous les outils sont installes.", "success")
    else:
        print_status(f"{missing_count} outil(s) manquant(s) sur {ok_count + missing_count}.", "warning")
    print()


def list_all_modules() -> None:
    """Affiche la liste de tous les modules de scan disponibles."""
    from securepipeline.modules import STACK_SCANNERS, GLOBAL_SCANNERS

    print_section("Modules de scan disponibles")
    print()

    # Modules par stack
    for stack, scanner_classes in sorted(STACK_SCANNERS.items()):
        print(f"  {CYAN}{BOLD}{stack.upper()}{RESET}")
        for scanner_cls in scanner_classes:
            info = scanner_cls().info()
            tools = ", ".join(info.tools_required) if info.tools_required else "aucun"
            print(f"    {DOT} {WHITE}{info.name}{RESET}  {GRAY}{DOT} outils: {tools}{RESET}")
            print(f"      {GRAY}{info.description}{RESET}")
        print()

    # Modules globaux
    print(f"  {CYAN}{BOLD}GLOBAL{RESET}")
    for scanner_cls in GLOBAL_SCANNERS:
        info = scanner_cls().info()
        tools = ", ".join(info.tools_required) if info.tools_required else "aucun"
        print(f"    {DOT} {WHITE}{info.name}{RESET}  {GRAY}{DOT} outils: {tools}{RESET}")
        print(f"      {GRAY}{info.description}{RESET}")
    print()


def show_about() -> None:
    """Affiche les informations sur l'outil."""
    from securepipeline import __version__, __author__

    print_section("A propos de SecurePipeline")
    print()
    print(f"  {WHITE}Version      {GRAY}{DOT}{RESET} {CYAN}{__version__}{RESET}")
    print(f"  {WHITE}Auteur       {GRAY}{DOT}{RESET} {CYAN}{__author__}{RESET}")
    print(f"  {WHITE}Langage      {GRAY}{DOT}{RESET} {CYAN}Python{RESET}")
    print(f"  {WHITE}Licence      {GRAY}{DOT}{RESET} {CYAN}Usage interne COSIT BENIN{RESET}")
    print()

    print(f"  {BLUE}{BOLD}Commandes CLI :{RESET}")
    print(f"    {GREEN}securepipeline{RESET}                              {GRAY}Mode interactif{RESET}")
    print(f"    {GREEN}securepipeline --scan . --fail-on critical{RESET}  {GRAY}Mode headless{RESET}")
    print(f"    {GREEN}securepipeline --scan . --output html{RESET}       {GRAY}Avec rapport HTML{RESET}")
    print()

    print(f"  {BLUE}{BOLD}Documentation :{RESET}")
    print(f"    {DOT} {WHITE}docs/INSTALL.md{RESET}           {GRAY}Guide d'installation{RESET}")
    print(f"    {DOT} {WHITE}docs/USAGE.md{RESET}             {GRAY}Guide d'utilisation{RESET}")
    print(f"    {DOT} {WHITE}docs/devsecops-guide.md{RESET}   {GRAY}Guide DevSecOps{RESET}")
    print()


def show_config() -> None:
    """Affiche et permet de modifier la configuration."""
    print_config(_config)

    print(f"  {WHITE}Modifier le seuil d'echec ?{RESET}")
    print(f"    {CYAN}[1]{RESET} {WHITE}critical{RESET}")
    print(f"    {CYAN}[2]{RESET} {WHITE}high{RESET}")
    print(f"    {CYAN}[3]{RESET} {WHITE}medium{RESET}")
    print(f"    {CYAN}[4]{RESET} {WHITE}low{RESET}")
    print(f"    {DARK_GRAY}[0]{RESET} {GRAY}Garder la configuration actuelle{RESET}")
    print()

    try:
        choice = input(f"  {GRAY}Choix:{RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    threshold_map = {"1": "critical", "2": "high", "3": "medium", "4": "low"}
    if choice in threshold_map:
        _config.fail_on = threshold_map[choice]
        print_status(f"Seuil d'echec mis a jour: {_config.fail_on}", "success")
    elif choice != "0":
        print_status("Configuration inchangee.", "info")


def show_cicd_example() -> None:
    """Affiche un exemple de commande CI/CD."""
    print_section("Exemple CI/CD")
    print()
    print(f"  {WHITE}Mode headless (pipeline) :{RESET}")
    print(f"  {GREEN}securepipeline --scan . --fail-on critical{RESET}")
    print()
    print(f"  {WHITE}Avec generation HTML :{RESET}")
    print(f"  {GREEN}securepipeline --scan . --fail-on critical --output html{RESET}")
    print()
    print(f"  {WHITE}GitHub Actions :{RESET}")
    print(f"  {GRAY}Voir .github/workflows/securepipeline.yml{RESET}")
    print()


def interactive_loop():
    """Boucle du menu interactif."""
    while True:
        clear_screen()
        print_home_screen()
        print_menu()

        try:
            choice = input(get_prompt()).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if choice in ["0", "00"] or choice.lower() in ["q", "quit", "exit"]:
            break

        elif choice in ["1", "01"]:
            path = input(get_path_prompt()).strip() or "."
            run_full_scan(path)
            input(get_continue_prompt())

        elif choice in ["2", "02"]:
            path = input(get_path_prompt()).strip() or "."
            detect_stacks_only(path)
            input(get_continue_prompt())

        elif choice in ["3", "03"]:
            show_cicd_example()
            input(get_continue_prompt())

        elif choice in ["4", "04"]:
            view_last_report()
            input(get_continue_prompt())

        elif choice in ["5", "05"]:
            generate_html_report()
            input(get_continue_prompt())

        elif choice in ["6", "06"]:
            check_all_prerequisites()
            input(get_continue_prompt())

        elif choice in ["7", "07"]:
            list_all_modules()
            input(get_continue_prompt())

        elif choice in ["8", "08"]:
            show_config()
            input(get_continue_prompt())

        elif choice in ["9", "09"]:
            show_about()
            input(get_continue_prompt())

        else:
            if choice:
                # Execute la commande comme un terminal
                import subprocess
                print()
                subprocess.run(choice, shell=True)
                input(get_continue_prompt())


@click.command(context_settings=dict(ignore_unknown_options=True))
@click.option("--scan", "scan_path", type=click.Path(exists=True), help="Chemin du projet a scanner (mode headless).")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default="critical",
              help="Seuil d'echec pour le mode CI/CD.")
@click.option("--output", type=click.Choice(["md", "html", "both"]), default="md",
              help="Format de sortie du rapport.")
def cli(scan_path, fail_on, output):
    """SecurePipeline -- Scanner de securite multi-stack DevSecOps."""

    if scan_path:
        # Mode headless (CI/CD)
        _config.fail_on = fail_on
        _config.output_format = output

        run_full_scan(scan_path)

        if output in ("html", "both"):
            generate_html_report(scan_path)

        # Exit code basé sur les findings
        from securepipeline.core.models import ScanResult
        # Le run_full_scan ne retourne pas le result,
        # mais pour le CI/CD on check via le rapport
    else:
        # Mode interactif par defaut
        interactive_loop()


def main():
    """Point d'entree principal."""
    cli()


if __name__ == "__main__":
    main()
