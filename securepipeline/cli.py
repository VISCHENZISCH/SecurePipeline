"""SecurePipeline - CLI interactif style Hacker/Forensic."""

import os
import sys
import time
from collections import defaultdict

import click

from securepipeline import __version__
from securepipeline.core.detector import detect_stacks
from securepipeline.core.orchestrator import run_scan
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
    DEB_RED, GREEN, CYAN, BLUE, WHITE, GRAY, RESET
)


def run_full_scan(path: str) -> None:
    """Exécute le scan complet et affiche les résultats."""
    print_section("Scan started")
    print(f"  {WHITE}Path:{RESET} {GRAY}{os.path.abspath(path)}{RESET}")
    stacks = detect_stacks(path)
    print_stacks(stacks)
    
    if not stacks:
        return

    from securepipeline.modules import get_scanners_for_stacks
    scanners = get_scanners_for_stacks(stacks)
    
    all_findings = []
    start_time = time.time()

    for scanner in scanners:
        info = scanner.info()
        print_scanner_start(info.name)

        ok, missing = scanner.check_prerequisites()
        if not ok:
            print_scanner_skip(f"missing: {','.join(missing)}")
            continue

        try:
            findings = scanner.scan(path)
            all_findings.extend(findings)
            print_scanner_done(len(findings))
        except Exception as e:
            print(f" {DEB_RED}ERR: {e}{RESET}")

    duration = time.time() - start_time
    
    stats: dict[str, int] = defaultdict(int)
    for f in all_findings:
        stats[f.severity.value] += 1

    print_summary(stats, len(all_findings), duration)
    print_findings_table(all_findings)
    
    # Generate report automatically
    from securepipeline.report.generator import generate_markdown, save_report
    from securepipeline.core.models import ScanResult
    
    result = ScanResult(findings=all_findings, stacks_scanned=stacks, duration_seconds=duration)
    md_report = generate_markdown(result, path, project_name=os.path.basename(os.path.abspath(path)))
    out_dir = os.path.join(path, ".securepipeline", "reports")
    report_file = save_report(md_report, out_dir)
    print(f"  {WHITE}Report:{RESET} {CYAN}{report_file}{RESET}\n")


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
            print_section("Exemple CI/CD")
            print(f"  {GREEN}securepipeline --scan . --fail-on critical{RESET}\n")
            input(get_continue_prompt())
            
        elif choice in ["3", "03", "88"]:
            print(f"\n  {DEB_RED}Fonctionnalite en cours de developpement.{RESET}")
            input(get_continue_prompt())
            
        elif choice in ["4", "04", "99"]:
            print(f"\n  {DEB_RED}Fonctionnalite en cours de developpement.{RESET}")
            input(get_continue_prompt())

        elif choice in ["5", "05"]:
            print(f"\n  {DEB_RED}Fonctionnalite en cours de developpement.{RESET}")
            input(get_continue_prompt())
            
        else:
            if choice:
                # Exécute la commande comme un vrai terminal Bash
                import subprocess
                print()
                subprocess.run(choice, shell=True, executable='/bin/bash')
                input(get_continue_prompt())


@click.command(context_settings=dict(ignore_unknown_options=True))
@click.option("--scan", "scan_path", type=click.Path(exists=True), help="Chemin du projet à scanner (mode headless).")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default="critical",
              help="Seuil d'échec pour le mode CI/CD.")
def cli(scan_path, fail_on):
    """SecurePipeline -- Scanner de securite multi-stack DevSecOps."""
    
    if scan_path:
        # Mode headless (CI/CD)
        run_full_scan(scan_path)
    else:
        # Mode interactif par defaut
        interactive_loop()


def main():
    """Point d'entree principal."""
    cli()


if __name__ == "__main__":
    main()
