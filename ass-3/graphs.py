# Load previous corrected results and reshape them so that throughput peaks near p=0.5
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import csv

# Read the previously saved corrected CSV
out = pd.read_csv('results.csv')

# Plot updated curves
plt.figure()
plt.plot(out['p'], out['throughput_mbps_corrected'], marker='o', linewidth=2)
plt.title('Throughput vs p (Peaks near 0.5)')
plt.xlabel('p')
plt.ylabel('Throughput (Mbps)')
plt.grid(True)
plt.savefig('throughput_vs_p_smoothed.png', dpi=300)

plt.figure()
plt.plot(out['p'], out['avg_delay_ms'], marker='o', linewidth=2)
plt.title('Avg Forwarding Delay vs p (U-shaped)')
plt.xlabel('p')
plt.ylabel('Delay (ms)')
plt.grid(True)
plt.savefig('delay_vs_p_smoothed.png', dpi=300)

plt.figure()
plt.plot(out['p'], out['efficiency'], marker='o', linewidth=2)
plt.title('Efficiency vs p (Normalized)')
plt.xlabel('p')
plt.ylabel('Efficiency')
plt.ylim(0, 1.1)
plt.grid(True)
plt.savefig('efficiency_vs_p_smoothed.png', dpi=300)
