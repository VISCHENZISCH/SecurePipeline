"""SecurePipeline - Orchestrateur de scans."""

import time

from securepipeline.core.models import Finding, ScanResult
from securepipeline.modules import get_scanners_for_stacks
from securepipeline.utils.logger import log


def run_scan(path: str, stacks: list[str]) -> ScanResult:
    """Lance un scan de sécurité sur le projet.

    Args:
        path: Chemin du projet.
        stacks: Liste des stacks détectées.

    Returns:
        Résultat agrégé du scan.
    """
    start_time = time.time()
    all_findings: list[Finding] = []
    
    scanners = get_scanners_for_stacks(stacks)
    log.info(f"Démarrage du scan avec {len(scanners)} modules: {[s.info().name for s in scanners]}")

    for scanner in scanners:
        scanner_info = scanner.info()
        log.info(f"Exécution du module : {scanner_info.name}")
        
        ok, missing = scanner.check_prerequisites()
        if not ok:
            log.warning(f"Outils manquants ignorés : {missing}")
            
        try:
            findings = scanner.scan(path)
            all_findings.extend(findings)
            log.info(f"Module {scanner_info.name} terminé. Findings: {len(findings)}")
        except Exception as e:
            log.error(f"Erreur lors de l'exécution de {scanner_info.name}: {e}")

    duration = time.time() - start_time
    result = ScanResult(
        findings=all_findings,
        stacks_scanned=stacks,
        duration_seconds=duration,
    )
    
    log.info(f"Scan terminé en {duration:.2f}s. Total findings: {result.total} (Critiques: {result.critical_count})")
    return result
