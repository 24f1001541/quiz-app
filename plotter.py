import base64
import io
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
from functools import lru_cache

# Color scheme consistent with your dashboard
COLOR_PRIMARY = '#4e73df'
COLOR_SUCCESS = '#1cc88a'
COLOR_DANGER = '#e74a3b'
COLOR_WARNING = '#f6c23e'
COLOR_INFO = '#36b9cc'
COLOR_BACKGROUND = '#f8f9fa'

def _apply_quiz_style(ax, title=None, ylabel=None):
    """Apply a consistent style to all charts with improved typography."""
    ax.set_facecolor(COLOR_BACKGROUND)
    plt.gcf().patch.set_facecolor(COLOR_BACKGROUND)
    
    # Clean up borders
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)
    for spine in ['left', 'bottom']:
        ax.spines[spine].set_color('#d1d3e2')
    
    # Styling
    ax.tick_params(axis='both', which='both', colors='#5a5c69', labelsize=10)
    ax.grid(axis='y', linestyle='--', alpha=0.4, color='#d1d3e2')
    
    if title:
        ax.set_title(title, pad=15, fontsize=14, fontweight='bold', color='#5a5c69')
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=11, color='#5a5c69', labelpad=10)

def _save_figure(fig):
    """Save a matplotlib figure to a base64-encoded string with optimized settings."""
    buffer = io.BytesIO()
    fig.savefig(
        buffer, 
        format='png', 
        dpi=100, 
        bbox_inches='tight', 
        facecolor=fig.get_facecolor(),
        transparent=False
    )
    plt.close(fig)
    buffer.seek(0)
    return f"data:image/png;base64,{base64.b64encode(buffer.read()).decode('utf-8')}"

def performance_plot(labels, values, title="Top Performers"):
    """
    Generate a horizontal bar plot for top performers with enhanced styling.
    Args:
        labels: List of student names
        values: List of percentage scores
        title: Chart title
    """
    fig, ax = plt.subplots(figsize=(10, 5))
    
    if not values or all(v == 0 for v in values):
        # Empty state handling
        ax.text(0.5, 0.5, 'No performance data available', 
               ha='center', va='center', 
               fontsize=12, color='#6c757d')
    else:
        # Create horizontal bars with conditional coloring
        bars = ax.barh(
            labels[::-1],  # Reverse to show highest at top
            values[::-1],
            color=[COLOR_SUCCESS if x >= 70 else COLOR_WARNING if x >= 40 else COLOR_DANGER for x in values[::-1]],
            height=0.6,
            edgecolor='white',
            linewidth=0.5
        )
        
        # Add value labels
        for bar in bars:
            width = bar.get_width()
            ax.text(
                width - 5 if width > 20 else width + 2,
                bar.get_y() + bar.get_height()/2,
                f'{width:.1f}%',
                va='center',
                ha='right' if width > 20 else 'left',
                color='white' if width > 60 else '#5a5c69',
                fontsize=10,
                fontweight='bold'
            )
    
    ax.set_xlim(0, 100)
    ax.xaxis.set_major_formatter(PercentFormatter())
    _apply_quiz_style(ax, title, 'Students')
    
    return _save_figure(fig)

def distribution_plot(scores, title="Score Distribution"):
    """
    Generate a histogram for score distribution with improved binning.
    Args:
        scores: List of percentage scores
        title: Chart title
    """
    fig, ax = plt.subplots(figsize=(10, 5))
    
    if not scores or all(s == 0 for s in scores):
        # Empty state handling
        ax.text(0.5, 0.5, 'No distribution data available', 
               ha='center', va='center', 
               fontsize=12, color='#6c757d')
    else:
        # Smart binning based on data range
        bins = 10
        if max(scores) - min(scores) < 20:  # Narrow range
            bins = 5
        
        n, bins, patches = ax.hist(
            scores,
            bins=bins,
            range=(0, 100),
            color=COLOR_PRIMARY,
            edgecolor='white',
            alpha=0.8,
            density=False
        )
        
        # Color bins based on performance
        for patch, bin_center in zip(patches, (bins[:-1] + bins[1:]) / 2):
            if bin_center >= 70:
                patch.set_facecolor(COLOR_SUCCESS)
            elif bin_center >= 40:
                patch.set_facecolor(COLOR_WARNING)
            else:
                patch.set_facecolor(COLOR_DANGER)
        
        # Add count labels for each bin
        for count, bin in zip(n, bins[:-1]):
            if count > 0:
                ax.text(
                    bin + (bins[1]-bins[0])/2,
                    count + 0.5,
                    str(int(count)),
                    ha='center',
                    va='bottom',
                    color='#5a5c69',
                    fontsize=9
                )
    
    ax.set_xlim(0, 100)
    ax.set_ylim(0, max(n)*1.1 if 'n' in locals() else 10)
    ax.xaxis.set_major_formatter(PercentFormatter())
    _apply_quiz_style(ax, title, 'Number of Students')
    
    return _save_figure(fig)