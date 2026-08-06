"""SecurePipeline - Widget d'arbre des modules de scan."""

from securepipeline.ui.display import (
    RESET, BOLD,
    CYAN, GREEN, GRAY, WHITE, DARK_GRAY, DEB_RED,
    BOX_V, BOX_H, BOX_TL, BOX_BL, BOX_LT,
    CIRCLE_F, CIRCLE_E, CHECK, CROSS, DIAMOND,
)


# Caractères d'arborescence
TREE_PIPE  = f"{DARK_GRAY}{BOX_V}{RESET}   "
TREE_TEE   = f"{DARK_GRAY}{BOX_LT}{BOX_H}{BOX_H}{RESET} "
TREE_ELBOW = f"{DARK_GRAY}{BOX_BL}{BOX_H}{BOX_H}{RESET} "
TREE_BLANK = "    "


def print_module_tree(scanners: list, stacks: list[str]) -> None:
    """Affiche l'arbre des modules de scan qui seront executes.

    Args:
        scanners: Liste d'instances de BaseScanner.
        stacks: Liste des stacks detectees.
    """
    print(f"\n  {CYAN}{BOLD}Modules de scan{RESET}")
    print(f"  {DARK_GRAY}{BOX_H * 30}{RESET}")
    print()

    # Grouper par stack
    by_stack: dict[str, list] = {}
    for scanner in scanners:
        info = scanner.info()
        stack = info.stack if info.stack else "global"
        if stack not in by_stack:
            by_stack[stack] = []
        by_stack[stack].append(info)

    stack_list = list(by_stack.keys())

    for i, stack in enumerate(stack_list):
        is_last_stack = (i == len(stack_list) - 1)
        connector = TREE_ELBOW if is_last_stack else TREE_TEE
        continuation = TREE_BLANK if is_last_stack else TREE_PIPE

        # Icone de stack
        if stack in stacks or stack == "global":
            icon = f"{GREEN}{CIRCLE_F}{RESET}"
        else:
            icon = f"{GRAY}{CIRCLE_E}{RESET}"

        print(f"  {connector}{icon} {WHITE}{BOLD}{stack.upper()}{RESET}")

        modules = by_stack[stack]
        for j, mod in enumerate(modules):
            is_last_mod = (j == len(modules) - 1)
            mod_connector = TREE_ELBOW if is_last_mod else TREE_TEE

            # Verifier les prerequis
            ok_text = f"{GREEN}{CHECK}{RESET}" if True else f"{DEB_RED}{CROSS}{RESET}"
            tools = ", ".join(mod.tools_required) if mod.tools_required else "aucun"

            print(f"  {continuation}{mod_connector}{ok_text} {CYAN}{mod.name}{RESET}")
            sub_cont = TREE_BLANK if is_last_mod else TREE_PIPE
            print(f"  {continuation}{sub_cont}  {GRAY}Outils: {tools}{RESET}")

    print()


def print_module_status_tree(results: dict[str, dict]) -> None:
    """Affiche l'arbre des resultats apres scan.

    Args:
        results: Dict {module_name: {"status": "ok"|"skip"|"error", "count": int}}
    """
    print(f"\n  {CYAN}{BOLD}Resultats par module{RESET}")
    print(f"  {DARK_GRAY}{BOX_H * 30}{RESET}")
    print()

    modules = list(results.keys())
    for i, name in enumerate(modules):
        is_last = (i == len(modules) - 1)
        connector = TREE_ELBOW if is_last else TREE_TEE
        data = results[name]

        status = data.get("status", "ok")
        count = data.get("count", 0)

        if status == "skip":
            icon = f"{GRAY}{CIRCLE_E}{RESET}"
            info = f"{GRAY}SKIP{RESET}"
        elif status == "error":
            icon = f"{DEB_RED}{CROSS}{RESET}"
            info = f"{DEB_RED}ERREUR{RESET}"
        elif count == 0:
            icon = f"{GREEN}{CHECK}{RESET}"
            info = f"{GREEN}OK{RESET}"
        else:
            icon = f"{DEB_RED}{DIAMOND}{RESET}"
            info = f"{DEB_RED}{count} finding(s){RESET}"

        print(f"  {connector}{icon} {WHITE}{name:<24}{RESET} {info}")

    print()
