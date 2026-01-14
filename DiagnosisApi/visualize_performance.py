#!/usr/bin/env python3
"""
Performance Visualization Script for Malaria Detection System
Creates comprehensive charts comparing all 4 parasite types
"""

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.patches import Rectangle
import pandas as pd

# Set style for better-looking charts
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

# Performance data from our analysis
species = ['PF', 'PM', 'PV', 'PO']
species_names = ['P. falciparum', 'P. malariae', 'P. vivax', 'P. ovale']

# Timing data (seconds per image)
individual_detection = [37.97, 29.51, 30.34, 26.41]
pipeline_analysis = [36.41, 27.60, 28.90, 13.40]
total_time = [74.37, 57.10, 59.24, 39.81]

# Confidence scores
confidence = [84.1, 94.7, 93.7, 93.2]

# Efficiency scores (relative to PF baseline)
efficiency = [1.0, 1.3, 1.25, 1.87]

# Create figure with multiple subplots
fig = plt.figure(figsize=(20, 16))
fig.suptitle('🧬 Malaria Detection System Performance Analysis\n40 Images Across 4 Plasmodium Species', 
             fontsize=24, fontweight='bold', y=0.98)

# 1. Speed Comparison Bar Chart
ax1 = plt.subplot(2, 3, 1)
bars1 = ax1.bar(species, total_time, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'], 
                alpha=0.8, edgecolor='black', linewidth=2)
ax1.set_title('⚡ Processing Speed Comparison\n(Seconds per Image)', fontsize=16, fontweight='bold', pad=20)
ax1.set_ylabel('Time per Image (seconds)', fontsize=14)
ax1.set_xlabel('Parasite Species', fontsize=14)

# Add value labels on bars
for bar, value in zip(bars1, total_time):
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
             f'{value:.1f}s', ha='center', va='bottom', fontweight='bold', fontsize=12)

# 2. Confidence Scores Comparison
ax2 = plt.subplot(2, 3, 2)
bars2 = ax2.bar(species, confidence, color=['#FFE66D', '#FF6B6B', '#4ECDC4', '#45B7D1'], 
                alpha=0.8, edgecolor='black', linewidth=2)
ax2.set_title('🎯 Detection Confidence Scores\n(Percentage)', fontsize=16, fontweight='bold', pad=20)
ax2.set_ylabel('Confidence (%)', fontsize=14)
ax2.set_xlabel('Parasite Species', fontsize=14)
ax2.set_ylim(0, 100)

# Add value labels on bars
for bar, value in zip(bars2, confidence):
    height = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2., height + 1,
             f'{value:.1f}%', ha='center', va='bottom', fontweight='bold', fontsize=12)

# 3. Efficiency Comparison
ax3 = plt.subplot(2, 3, 3)
bars3 = ax3.bar(species, efficiency, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'], 
                alpha=0.8, edgecolor='black', linewidth=2)
ax3.set_title('🚀 Processing Efficiency\n(Relative to PF Baseline)', fontsize=16, fontweight='bold', pad=20)
ax3.set_ylabel('Efficiency Multiplier', fontsize=14)
ax3.set_xlabel('Parasite Species', fontsize=14)

# Add value labels on bars
for bar, value in zip(bars3, efficiency):
    height = bar.get_height()
    ax3.text(bar.get_x() + bar.get_width()/2., height + 0.05,
             f'{value:.2f}x', ha='center', va='bottom', fontweight='bold', fontsize=12)

# 4. Stacked Bar Chart - Individual vs Pipeline
ax4 = plt.subplot(2, 3, 4)
x = np.arange(len(species))
width = 0.35

bars4a = ax4.bar(x - width/2, individual_detection, width, label='Individual Detection', 
                  color='#FF6B6B', alpha=0.8, edgecolor='black')
bars4b = ax4.bar(x + width/2, pipeline_analysis, width, label='Pipeline Analysis', 
                  color='#4ECDC4', alpha=0.8, edgecolor='black')

ax4.set_title('📊 Processing Time Breakdown\n(Individual vs Pipeline)', fontsize=16, fontweight='bold', pad=20)
ax4.set_ylabel('Time (seconds)', fontsize=14)
ax4.set_xlabel('Parasite Species', fontsize=14)
ax4.set_xticks(x)
ax4.set_xticklabels(species)
ax4.legend(fontsize=12)

# Add value labels
for bars in [bars4a, bars4b]:
    for bar in bars:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                 f'{height:.1f}s', ha='center', va='bottom', fontsize=10, fontweight='bold')

# 5. Radar Chart for Overall Performance
ax5 = plt.subplot(2, 3, 5, projection='polar')

# Normalize values for radar chart (0-1 scale)
norm_time = [1 - (t - min(total_time)) / (max(total_time) - min(total_time)) for t in total_time]
norm_conf = [c / 100 for c in confidence]
norm_eff = [e / max(efficiency) for e in efficiency]

# Calculate overall performance score
overall_score = [(norm_time[i] + norm_conf[i] + norm_eff[i]) / 3 for i in range(len(species))]

# Radar chart angles
angles = np.linspace(0, 2 * np.pi, len(species), endpoint=False).tolist()
angles += angles[:1]  # Complete the circle

# Add overall performance to the radar
overall_score += overall_score[:1]

ax5.plot(angles, overall_score, 'o-', linewidth=3, color='#FF6B6B', label='Overall Performance')
ax5.fill(angles, overall_score, alpha=0.25, color='#FF6B6B')
ax5.set_title('🎯 Overall Performance Radar\n(Combined Metrics)', fontsize=16, fontweight='bold', pad=30)
ax5.set_xticks(angles[:-1])
ax5.set_xticklabels(species, fontsize=12)
ax5.set_ylim(0, 1)
ax5.grid(True)

# 6. Performance Summary Table
ax6 = plt.subplot(2, 3, 6)
ax6.axis('tight')
ax6.axis('off')

# Create summary table
table_data = [
    ['Species', 'Time/Image', 'Confidence', 'Efficiency', 'Rank'],
    ['PF', '74.37s', '84.1%', '1.0x', '4th'],
    ['PM', '57.10s', '94.7%', '1.3x', '2nd'],
    ['PV', '59.24s', '93.7%', '1.25x', '3rd'],
    ['PO', '39.81s', '93.2%', '1.87x', '1st']
]

table = ax6.table(cellText=table_data[1:], colLabels=table_data[0], 
                  cellLoc='center', loc='center', 
                  colWidths=[0.2, 0.25, 0.25, 0.2, 0.1])

# Style the table
table.auto_set_font_size(False)
table.set_fontsize(12)
table.scale(1, 2)

# Color code the table
for i in range(len(table_data[0])):
    table[(0, i)].set_facecolor('#4ECDC4')
    table[(0, i)].set_text_props(weight='bold', color='white')

# Color code the ranks
rank_colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
for i in range(1, len(table_data)):
    table[(i, 0)].set_facecolor(rank_colors[i-1])
    table[(i, 0)].set_text_props(weight='bold', color='white')
    table[(i, 4)].set_facecolor(rank_colors[i-1])  # Fixed: use 4 instead of -1 for last column
    table[(i, 4)].set_text_props(weight='bold', color='white')

ax6.set_title('📋 Performance Summary Table', fontsize=16, fontweight='bold', pad=20)

# Adjust layout and save
plt.tight_layout()
plt.subplots_adjust(top=0.92, bottom=0.05, left=0.05, right=0.95)

# Save the comprehensive visualization
plt.savefig('performance_comparison_visualization.png', dpi=300, bbox_inches='tight')
print("✅ Performance visualization saved as 'performance_comparison_visualization.png'")

# Show the plot
plt.show()

# Create additional specialized charts
fig2, (ax7, ax8) = plt.subplots(1, 2, figsize=(16, 8))
fig2.suptitle('🔬 Detailed Performance Analysis', fontsize=20, fontweight='bold')

# 7. Speed vs Confidence Scatter Plot
ax7.scatter(total_time, confidence, s=200, c=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'], 
            alpha=0.8, edgecolors='black', linewidth=2)

# Add labels for each point
for i, (x, y) in enumerate(zip(total_time, confidence)):
    ax7.annotate(species[i], (x, y), xytext=(5, 5), textcoords='offset points', 
                 fontsize=12, fontweight='bold')

ax7.set_xlabel('Processing Time per Image (seconds)', fontsize=14)
ax7.set_ylabel('Detection Confidence (%)', fontsize=14)
ax7.set_title('⚡ Speed vs Accuracy Trade-off', fontsize=16, fontweight='bold')
ax7.grid(True, alpha=0.3)

# Add efficiency annotations
ax7.annotate('Most Efficient\n(PO)', xy=(39.81, 93.2), xytext=(50, 85),
             arrowprops=dict(arrowstyle='->', color='red', lw=2),
             fontsize=12, fontweight='bold', color='red')

ax7.annotate('Most Accurate\n(PM)', xy=(57.10, 94.7), xytext=(65, 90),
             arrowprops=dict(arrowstyle='->', color='blue', lw=2),
             fontsize=12, fontweight='bold', color='blue')

# 8. Performance Heatmap
performance_matrix = np.array([
    [norm_time[0], norm_conf[0], norm_eff[0]],  # PF
    [norm_time[1], norm_conf[1], norm_eff[1]],  # PM
    [norm_time[2], norm_conf[2], norm_eff[2]],  # PV
    [norm_time[3], norm_conf[3], norm_eff[3]]   # PO
])

im = ax8.imshow(performance_matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
ax8.set_xticks([0, 1, 2])
ax8.set_xticklabels(['Speed\n(Norm)', 'Confidence\n(Norm)', 'Efficiency\n(Norm)'], fontsize=12)
ax8.set_yticks([0, 1, 2, 3])
ax8.set_yticklabels(species, fontsize=12, fontweight='bold')

# Add value annotations
for i in range(4):
    for j in range(3):
        text = ax8.text(j, i, f'{performance_matrix[i, j]:.2f}',
                        ha="center", va="center", color="black", fontweight='bold', fontsize=11)

ax8.set_title('🔥 Performance Heatmap\n(Normalized Scores)', fontsize=16, fontweight='bold')

# Add colorbar
cbar = plt.colorbar(im, ax=ax8, shrink=0.8)
cbar.set_label('Normalized Performance Score', fontsize=12)

plt.tight_layout()
plt.savefig('detailed_performance_analysis.png', dpi=300, bbox_inches='tight')
print("✅ Detailed analysis visualization saved as 'detailed_performance_analysis.png'")

plt.show()

print("\n🎉 All visualizations completed successfully!")
print("📊 Generated charts:")
print("  1. performance_comparison_visualization.png - Comprehensive 6-panel analysis")
print("  2. detailed_performance_analysis.png - Speed vs Accuracy + Heatmap")
