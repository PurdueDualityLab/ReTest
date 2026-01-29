"""Chart generation for baseline comparison experiments.

This module generates line charts comparing coverage over time
across different fuzzing strategies and engines.

Uses publication-quality styling consistent with ICSE paper figures.
"""

from pathlib import Path
from typing import Dict, List, Tuple

from loguru import logger

from re_fuzzer.experiments.experiment_config import CoverageSnapshot


# Colorblind-friendly color palette for different strategies
# Based on Wong (2011) "Points of view: Color blindness" Nature Methods
STRATEGY_COLORS = {
    "naive": "#CC3311",    # Red
    "grammar": "#0077BB",  # Blue
    "retest": "#009988",   # Teal
}

# Line styles for different strategies (consistent across charts)
STRATEGY_LINESTYLES = {
    "naive": "-",     # Solid
    "grammar": "--",  # Dashed
    "retest": "-.",   # Dash-dot
}

# Markers for different strategies
STRATEGY_MARKERS = {
    "naive": "s",     # Square
    "grammar": "^",   # Triangle
    "retest": "o",    # Circle
}


def _configure_publication_style():
    """Configure matplotlib for publication-quality figures."""
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        'font.family': 'serif',
        'font.size': 9,
        'axes.labelsize': 9,
        'axes.titlesize': 10,
        'xtick.labelsize': 8,
        'ytick.labelsize': 8,
        'legend.fontsize': 8,
        'figure.dpi': 300,
        'savefig.dpi': 300,
        'savefig.bbox': 'tight',
        'savefig.pad_inches': 0.05,
    })


class ChartGenerator:
    """Generates comparison charts for fuzzing experiments.

    Uses publication-quality styling for ICSE paper figures.
    """

    def __init__(
        self,
        figsize: Tuple[float, float] = (3.5, 2.5),  # Single column width
        dpi: int = 300,
        use_publication_style: bool = True,
    ):
        """Initialize chart generator.

        Args:
            figsize: Figure size in inches (width, height). Default 3.5" for single column.
            dpi: Resolution for saved figures (300 for publication)
            use_publication_style: Whether to use publication-quality styling
        """
        self.figsize = figsize
        self.dpi = dpi
        self.use_publication_style = use_publication_style

    def generate_coverage_chart(
        self,
        timelines: Dict[str, List[CoverageSnapshot]],
        title: str,
        output_path: Path,
        time_unit: str = "minutes",
        show_markers: bool = True,
    ) -> bool:
        """Generate line chart comparing coverage over time.

        Args:
            timelines: Dict mapping experiment name to snapshot list
            title: Chart title
            output_path: Path to save the chart (will also save .pdf version)
            time_unit: Time unit for x-axis ("seconds", "minutes", "hours")
            show_markers: Whether to show markers on data points

        Returns:
            True if chart was generated successfully
        """
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            logger.error("matplotlib not installed. Install with: pip install matplotlib")
            return False

        # Apply publication-quality styling
        if self.use_publication_style:
            _configure_publication_style()

        # Filter empty timelines
        timelines = {k: v for k, v in timelines.items() if v}
        if not timelines:
            logger.warning("No data to plot")
            return False

        # Create figure
        _, ax = plt.subplots(figsize=self.figsize)

        # Time conversion factor
        time_divisor = {"seconds": 1, "minutes": 60, "hours": 3600}.get(time_unit, 60)

        # Plot each timeline
        for name, snapshots in sorted(timelines.items()):
            if not snapshots:
                continue

            times = [s.elapsed_seconds / time_divisor for s in snapshots]
            edges = [s.unique_edges for s in snapshots]

            # Determine color, style, and marker from name
            color = self._get_color(name)
            linestyle = self._get_linestyle(name)
            marker = self._get_marker(name) if show_markers else None
            markersize = 4 if show_markers else 0

            ax.plot(
                times,
                edges,
                label=self._format_label(name),
                color=color,
                linestyle=linestyle,
                marker=marker,
                markersize=markersize,
                linewidth=1.5,
                markeredgewidth=0.5,
                markeredgecolor='white',
            )

        # Formatting (sizes controlled by rcParams)
        ax.set_xlabel(f"Time ({time_unit})")
        ax.set_ylabel("Unique Edges Covered")

        # Legend below the plot (publication style)
        ax.legend(
            loc='upper center',
            bbox_to_anchor=(0.5, -0.18),
            ncol=3,
            frameon=False,
            columnspacing=0.8,
        )

        # Grid with subtle styling
        ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)

        # Ensure y-axis starts at 0
        ax.set_ylim(bottom=0)

        # Tight layout
        plt.tight_layout()

        # Save as both PNG and PDF
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # PNG version
        plt.savefig(output_path, format='png', dpi=self.dpi, bbox_inches='tight')

        # PDF version for publication
        pdf_path = output_path.with_suffix('.pdf')
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')

        plt.close()

        logger.info(f"Saved chart to {output_path} and {pdf_path}")
        return True

    def generate_comparison_charts(
        self,
        all_timelines: Dict[str, List[CoverageSnapshot]],
        output_dir: Path,
    ) -> List[Path]:
        """Generate multiple comparison charts.

        Generates:
        - One chart for PCRE engine (all strategies)
        - One chart for PCRE2 engine (all strategies)
        - One chart for all experiments combined

        Args:
            all_timelines: Dict mapping experiment name to snapshot list
            output_dir: Directory to save charts

        Returns:
            List of generated chart paths
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        generated = []

        # Separate by engine
        pcre_timelines = {k: v for k, v in all_timelines.items() if "pcre2" not in k.lower()}
        pcre2_timelines = {k: v for k, v in all_timelines.items() if "pcre2" in k.lower()}

        # PCRE chart
        if pcre_timelines:
            path = output_dir / "pcre_coverage.png"
            if self.generate_coverage_chart(
                pcre_timelines,
                "PCRE 8.45 Coverage Comparison",
                path,
            ):
                generated.append(path)

        # PCRE2 chart
        if pcre2_timelines:
            path = output_dir / "pcre2_coverage.png"
            if self.generate_coverage_chart(
                pcre2_timelines,
                "PCRE2 10.47 Coverage Comparison",
                path,
            ):
                generated.append(path)

        # Combined chart
        if all_timelines:
            path = output_dir / "combined_coverage.png"
            if self.generate_coverage_chart(
                all_timelines,
                "All Experiments Coverage Comparison",
                path,
            ):
                generated.append(path)

        return generated

    def generate_bug_chart(
        self,
        bug_counts: Dict[str, int],
        title: str,
        output_path: Path,
    ) -> bool:
        """Generate bar chart showing bugs found by each strategy.

        Args:
            bug_counts: Dict mapping experiment name to bug count
            title: Chart title
            output_path: Path to save the chart

        Returns:
            True if chart was generated successfully
        """
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            logger.error("matplotlib not installed")
            return False

        if not bug_counts:
            return False

        # Apply publication-quality styling
        if self.use_publication_style:
            _configure_publication_style()

        _, ax = plt.subplots(figsize=(3.5, 2.5))

        names = list(bug_counts.keys())
        counts = list(bug_counts.values())
        colors = [self._get_color(name) for name in names]

        bars = ax.bar(names, counts, color=colors, edgecolor="white", linewidth=0.5)

        # Optional title (usually omitted for publication, goes in caption)
        if title:
            ax.set_title(title)

        # Add value labels on bars
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax.annotate(
                f"{count}",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 2),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=7,
            )

        ax.set_xlabel("Experiment")
        ax.set_ylabel("Bugs Found")
        ax.set_ylim(bottom=0)

        # Format x-axis labels
        ax.set_xticklabels([self._format_label(n) for n in names], rotation=45, ha="right")
        plt.tight_layout()

        # Save as both PNG and PDF
        output_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path, format='png', dpi=self.dpi, bbox_inches="tight")
        pdf_path = output_path.with_suffix('.pdf')
        plt.savefig(pdf_path, format='pdf', bbox_inches="tight")
        plt.close()

        logger.info(f"Saved bug chart to {output_path} and {pdf_path}")
        return True

    def _get_color(self, name: str) -> str:
        """Get color for experiment based on strategy.

        Args:
            name: Experiment name (e.g., "naive_pcre", "grammar_pcre2")

        Returns:
            Hex color code
        """
        name_lower = name.lower()
        for strategy, color in STRATEGY_COLORS.items():
            if strategy in name_lower:
                return color
        return "#7F8C8D"  # Default gray

    def _get_linestyle(self, name: str) -> str:
        """Get line style for experiment based on strategy.

        Args:
            name: Experiment name

        Returns:
            Matplotlib linestyle string
        """
        name_lower = name.lower()
        for strategy, linestyle in STRATEGY_LINESTYLES.items():
            if strategy in name_lower:
                return linestyle
        return "-"  # Default solid

    def _get_marker(self, name: str) -> str:
        """Get marker style for experiment based on strategy.

        Args:
            name: Experiment name

        Returns:
            Matplotlib marker string
        """
        name_lower = name.lower()
        for strategy, marker in STRATEGY_MARKERS.items():
            if strategy in name_lower:
                return marker
        return "o"  # Default circle

    def _format_label(self, name: str) -> str:
        """Format experiment name for legend label.

        Args:
            name: Raw experiment name (e.g., "retest_pcre2", "naive_pcre")

        Returns:
            Formatted label (e.g., "ReTest", "Naive", "Grammar")
        """
        name_lower = name.lower()

        # Determine strategy name only (engine is indicated by line style)
        if "retest" in name_lower:
            return "ReTest"
        elif "grammar" in name_lower:
            return "Grammar"
        elif "naive" in name_lower:
            return "Naive"
        else:
            return name.split("_")[0].title()


def quick_coverage_chart(
    timelines: Dict[str, List[CoverageSnapshot]],
    output_path: Path,
    title: str = "Coverage Over Time",
) -> bool:
    """Convenience function to quickly generate a coverage chart.

    Args:
        timelines: Dict mapping experiment name to snapshot list
        output_path: Path to save the chart
        title: Chart title

    Returns:
        True if chart was generated successfully
    """
    generator = ChartGenerator()
    return generator.generate_coverage_chart(timelines, title, output_path)
