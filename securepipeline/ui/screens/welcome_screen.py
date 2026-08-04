"""SecurePipeline - Écran d'accueil / Welcome Screen (Dashboard Layout)."""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import Static, Header, Footer, Button, Label, Input
from textual import on

from securepipeline import __version__, __author__
from securepipeline.ui.banner import SHIELD_ART, TAGLINE, SUBTITLE
from securepipeline.ui.theme import COLORS


# ── Constantes d'affichage ───────────────────────────────────────────

FEATURES = [
    ("</> Multi-Stack", "Supporte Python, Node.js, PHP, Docker, K8s, Flutter et plus encore.", "primary"),
    ("⚡ Rapide", "Scans parallèles avec orchestration intelligente pour des résultats rapides.", "warning"),
    ("🔒 Secrets", "Détection avancée de clés API, tokens, mots de passe et credentials.", "error"),
    ("🛡️ DevSecOps", "Intégration continue avec CI/CD et seuils de sécurité configurables.", "info"),
    ("📊 Rapports", "Export Markdown & HTML avec tableaux de bord interactifs.", "success"),
    ("⚙ Extensible", "Architecture modulaire pour ajouter vos propres scanners et règles.", "primary"),
]


# ── Composants de la Sidebar (Gauche) ────────────────────────────────

class SidebarMenu(Vertical):
    """Menu de navigation latéral."""

    DEFAULT_CSS = """
    SidebarMenu {
        width: 30;
        height: 100%;
        background: #111827;
        border-right: solid #1e2d3d;
        padding: 1 0;
    }
    
    .sidebar-title {
        color: #e2e8f0;
        text-style: bold;
        padding: 1 2;
        margin-bottom: 1;
    }
    
    .menu-item {
        width: 100%;
        height: 3;
        padding: 1 2;
        color: #8892a4;
        background: transparent;
        border: none;
        content-align: left middle;
    }
    
    .menu-item:hover {
        background: #1f2d40;
        color: #e2e8f0;
    }
    
    .menu-item.-active {
        background: #1a2332;
        color: #00d4aa;
        border-left: thick #00d4aa;
    }
    
    #pro-banner {
        dock: bottom;
        height: auto;
        padding: 1 2;
        margin: 1;
        background: #1a2332;
        border: round #1e2d3d;
    }
    
    #btn-pro {
        width: 100%;
        margin-top: 1;
        background: transparent;
        color: #00d4aa;
        border: solid #00d4aa;
    }
    
    #btn-pro:hover {
        background: #00d4aa;
        color: #0a0e17;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label("⎔ SECUREPIPELINE", classes="sidebar-title")
        
        yield Button("🏠 Tableau de bord", classes="menu-item -active", id="nav_dash")
        yield Button("▶ Lancer un scan", classes="menu-item", id="nav_scan")
        yield Button("📊 Rapports", classes="menu-item", id="nav_reports")
        yield Button("🕒 Historique", classes="menu-item", id="nav_history")
        yield Button("🔒 Secrets", classes="menu-item", id="nav_secrets")
        yield Button("⚙ Configurations", classes="menu-item", id="nav_config")
        
        with Vertical(id="pro-banner"):
            yield Label("[bold #e2e8f0]🚀 SecurePipeline Pro[/]")
            yield Label("[dim #8892a4]Débloquez des fonctionnalités avancées.[/]")
            yield Button("Passer en Pro", id="btn-pro")


# ── Composants de la Zone Principale ─────────────────────────────────

class TopBar(Horizontal):
    """Barre de recherche en haut."""
    
    DEFAULT_CSS = """
    TopBar {
        height: 3;
        width: 100%;
        margin-bottom: 1;
        align: left middle;
    }
    
    Input {
        width: 40;
        height: 3;
        background: #111827;
        border: none;
        color: #e2e8f0;
    }
    
    .top-actions {
        width: 1fr;
        content-align: right middle;
        color: #8892a4;
    }
    """
    
    def compose(self) -> ComposeResult:
        yield Input(placeholder="🔍 Rechercher (Ctrl + K)")
        yield Label("📖 Documentation   🔔   👤", classes="top-actions")


class HeroBanner(Horizontal):
    """Bannière principale avec bouclier et titre."""
    
    DEFAULT_CSS = """
    HeroBanner {
        height: 12;
        width: 100%;
        background: #111827;
        border: round #1e2d3d;
        margin-bottom: 2;
        align: center middle;
    }
    
    .hero-shield {
        width: 25;
        color: #00d4aa;
        content-align: center middle;
    }
    
    .hero-text {
        width: 1fr;
        padding-left: 2;
        align: left middle;
    }
    
    .hero-title {
        color: #e2e8f0;
        text-style: bold;
    }
    
    .hero-subtitle {
        color: #8892a4;
        margin-bottom: 1;
    }
    
    .hero-tags {
        color: #00d4aa;
        text-style: bold;
    }
    """
    
    def compose(self) -> ComposeResult:
        yield Label(SHIELD_ART, classes="hero-shield")
        with Vertical(classes="hero-text"):
            yield Label("SECUREPIPELINE", classes="hero-title")
            yield Label("DevSecOps Multi-Stack Security Scanner", classes="hero-subtitle")
            yield Label("ANALYSER   •   DÉTECTER   •   SÉCURISER", classes="hero-tags")


class ReadyToScanBanner(Horizontal):
    """Bannière 'Prêt à scanner'."""
    
    DEFAULT_CSS = """
    ReadyToScanBanner {
        height: 5;
        width: 100%;
        background: #1a2332;
        border: round #1e2d3d;
        margin-bottom: 2;
        align: space-between middle;
        padding: 0 2;
    }
    
    .ready-text {
        color: #e2e8f0;
        text-style: bold;
    }
    
    .ready-sub {
        color: #8892a4;
    }
    
    #btn-main-scan {
        background: #00d4aa;
        color: #0a0e17;
        border: none;
        height: 3;
    }
    
    #btn-main-scan:hover {
        background: #00f0c0;
    }
    """
    
    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Prêt à scanner votre projet ?", classes="ready-text")
            yield Label("Lancez une analyse complète en quelques clics.", classes="ready-sub")
        yield Button("+ Lancer un Scan >", id="btn-main-scan")


class FeatureCard(Static):
    """Carte individuelle pour une fonctionnalité."""

    DEFAULT_CSS = """
    FeatureCard {
        width: 1fr;
        height: 7;
        padding: 1 2;
        background: #111827;
        border: round #1e2d3d;
    }

    FeatureCard:hover {
        border: round #00d4aa;
        background: #1f2d40;
    }
    
    .feat-title {
        color: #e2e8f0;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .feat-desc {
        color: #8892a4;
        height: 2;
    }
    
    .feat-link {
        color: #4a5568;
        margin-top: 1;
    }
    """

    def __init__(self, title: str, description: str) -> None:
        content = (
            f"[bold #e2e8f0]{title}[/]\n"
            f"[#8892a4]{description}[/]\n\n"
            f"[dim #4a5568]Détails →[/]"
        )
        super().__init__(content)


class FeaturesGrid(Grid):
    """Grille des fonctionnalités."""

    DEFAULT_CSS = """
    FeaturesGrid {
        width: 100%;
        height: auto;
        grid-size: 3;
        grid-gutter: 1 2;
        margin-bottom: 2;
    }
    """

    def compose(self) -> ComposeResult:
        for title, desc, _ in FEATURES:
            yield FeatureCard(title, desc)


class MainContent(Vertical):
    """Zone principale de droite."""
    
    DEFAULT_CSS = """
    MainContent {
        width: 1fr;
        height: 100%;
        padding: 1 4;
        background: #0a0e17;
        overflow-y: auto;
    }
    
    .section-title {
        color: #e2e8f0;
        text-style: bold;
        margin-bottom: 1;
    }
    """
    
    def compose(self) -> ComposeResult:
        yield TopBar()
        yield HeroBanner()
        yield ReadyToScanBanner()
        
        yield FeaturesGrid()
        yield Label(f"[dim #4a5568]v{__version__} | par {__author__} | Python CLI DevSecOps[/]", id="footer-credits")


# SecurePipeline::Écran Principal

class WelcomeScreen(Screen):
    """Écran d'accueil principal (Dashboard)."""

    CSS = """
    WelcomeScreen {
        background: #0a0e17;
        layout: horizontal;
    }
    
    #footer-credits {
        width: 100%;
        content-align: center middle;
        margin-top: 2;
    }
    """

    BINDINGS = [
        ("q", "quit_app", "Quitter"),
        ("s", "start_scan", "Scanner"),
    ]

    def __init__(
        self,
        path: str = ".",
        stacks: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.scan_path = path
        self.stacks = stacks or []

    def compose(self) -> ComposeResult:
        yield SidebarMenu()
        yield MainContent()

    # ── Handlers ─────────────────────────────────────────────────────

    @on(Button.Pressed, "#btn-main-scan")
    @on(Button.Pressed, "#nav_scan")
    def on_scan_pressed(self) -> None:
        self.notify(
            f"🔍 Lancement du scan sur : {self.scan_path}",
            title="SecurePipeline",
            severity="information",
        )

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        # Ignore main scan buttons handled above
        if event.button.id in ["btn-main-scan", "nav_scan"]:
            return
            
        if event.button.id == "btn-pro":
            self.notify("Redirection vers la page d'abonnement...", title="Pro")
        elif event.button.id == "nav_reports":
            self.notify("Ouverture du tableau de bord des rapports", title="Rapports")
        elif event.button.id == "nav_config":
            self.notify("Paramètres du pipeline de sécurité", title="Configuration")
        else:
            # Effet visuel de menu
            for btn in self.query(".menu-item"):
                btn.remove_class("-active")
            if "menu-item" in event.button.classes:
                event.button.add_class("-active")

    def action_quit_app(self) -> None:
        self.app.exit()

    def action_start_scan(self) -> None:
        self.on_scan_pressed()
