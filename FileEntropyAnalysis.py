"""
File Entropy Analysis Program

Description:
This program analyzes the entropy of binary files in chunks. Entropy measures randomness or unpredictability in data, making it useful for identifying regions that are encrypted or compressed. The program performs the following steps:
1. Reads a binary file in chunks of specified sizes.
2. Calculates the entropy for each chunk using probability distributions of byte values.
3. Plots the entropy values to visualize the randomness of the data.

Use Case:
This tool is particularly helpful for reverse engineering or digital forensics tasks to locate potentially sensitive or encrypted regions in binary files.

Dependencies:
- numpy: For numerical operations.
- matplotlib: For plotting entropy values.
"""
import numpy as np
import matplotlib.pyplot as plt
import math

def calculate_entropy(data):
    if len(data) == 0:
        return 0

    byte_counts = np.bincount(data, minlength=256)
    probabilities = byte_counts / len(data)
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-12))
    return entropy

def read_and_calculate_entropy(filename, chunk_size=1024):
    entropy_values = []
    with open(filename, 'rb') as file:
        while chunk := file.read(chunk_size):
            data = np.frombuffer(chunk, dtype=np.uint8)
            entropy = calculate_entropy(data)
            entropy_values.append(entropy)
    return entropy_values

def plot_entropy(entropy_values_dict):
    plt.figure(figsize=(12, 8))
    for chunk_size, entropy_values in entropy_values_dict.items():
        plt.plot(entropy_values, marker='o', linestyle='-', label=f'Chunk Size = {chunk_size} bytes')
    plt.title('Entropy of Flash Dump File at Different Chunk Sizes')
    plt.xlabel('Chunk Index')
    plt.ylabel('Entropy')
    plt.legend()
    plt.grid(True)
    plt.show()

def main():
    filename = 'example.bin'
    chunk_sizes = [4096]
    entropy_values_dict = {}
    for chunk_size in chunk_sizes:
        entropy_values = read_and_calculate_entropy(filename, chunk_size)
        entropy_values_dict[chunk_size] = entropy_values
    plot_entropy(entropy_values_dict)

if __name__ == '__main__':
    main()
