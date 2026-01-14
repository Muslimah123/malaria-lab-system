import matplotlib.pyplot as plt
import numpy as np

# Data from our analysis
species = ['PF', 'PM', 'PV', 'PO']
names = ['P. falciparum', 'P. malariae', 'P. vivax', 'P. ovale']
time_per_image = [74.37, 57.10, 59.24, 39.81]
confidence = [84.1, 94.7, 93.7, 93.2]
efficiency = [1.0, 1.3, 1.25, 1.87]

# Create figure with subplots
fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
fig.suptitle('Malaria Detection System Performance Analysis', fontsize=16, fontweight='bold')

# 1. Speed comparison
bars1 = ax1.bar(species, time_per_image, color=['red', 'blue', 'orange', 'green'])
ax1.set_title('Processing Speed (seconds per image)')
ax1.set_ylabel('Time (seconds)')
for bar, value in zip(bars1, time_per_image):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
             f'{value:.1f}s', ha='center', va='bottom', fontweight='bold')

# 2. Confidence scores
bars2 = ax2.bar(species, confidence, color=['red', 'blue', 'orange', 'green'])
ax2.set_title('Detection Confidence (%)')
ax2.set_ylabel('Confidence (%)')
ax2.set_ylim(0, 100)
for bar, value in zip(bars2, confidence):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
             f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

# 3. Efficiency comparison
bars3 = ax3.bar(species, efficiency, color=['red', 'blue', 'orange', 'green'])
ax3.set_title('Processing Efficiency (relative to PF)')
ax3.set_ylabel('Efficiency Multiplier')
for bar, value in zip(bars3, efficiency):
    ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05, 
             f'{value:.2f}x', ha='center', va='bottom', fontweight='bold')

# 4. Performance summary table
ax4.axis('tight')
ax4.axis('off')
table_data = [
    ['Species', 'Time/Image', 'Confidence', 'Efficiency', 'Rank'],
    ['PF', '74.37s', '84.1%', '1.0x', '4th'],
    ['PM', '57.10s', '94.7%', '1.3x', '2nd'],
    ['PV', '59.24s', '93.7%', '1.25x', '3rd'],
    ['PO', '39.81s', '93.2%', '1.87x', '1st']
]
table = ax4.table(cellText=table_data[1:], colLabels=table_data[0], 
                  cellLoc='center', loc='center')
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1, 2)

plt.tight_layout()
plt.savefig('performance_charts.png', dpi=300, bbox_inches='tight')
plt.show()

print("Charts saved as 'performance_charts.png'")
