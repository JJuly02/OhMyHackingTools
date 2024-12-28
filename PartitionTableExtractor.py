"""
Partition Table Reader and Extractor

Description:
This program reads a partition table from a binary file and extracts each partition based on the table's information. It performs the following:
1. Reads partition table data from a specified range in the binary file.
2. Parses the partition table to extract partition names, offsets, and sizes.
3. Extracts each partition as a separate binary file and saves it to an output folder.

Use Case:
Useful for analyzing embedded systems' firmware where partitions like bootloaders, file systems, or configurations need to be extracted.

Dependencies:
- struct: For unpacking binary data.
"""
import os
import struct

def read_partition_table(file_path, start_offset, end_offset):
    with open(file_path, 'rb') as f:
        f.seek(start_offset)
        partition_table_data = f.read(end_offset - start_offset)
    return partition_table_data

def parse_partition_table(partition_table_data):
    partitions = []
    entry_size = 32
    for i in range(0, len(partition_table_data), entry_size):
        entry = partition_table_data[i:i + entry_size]
        if len(entry) < entry_size:
            break
        name = entry[12:28].decode('utf-8').strip('\x00')
        offset = struct.unpack('<I', entry[4:8])[0]
        size = struct.unpack('<I', entry[8:12])[0]
        partitions.append((name, offset, size))
    return partitions

def extract_partitions(file_path, partitions, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(file_path, 'rb') as f:
        for name, offset, size in partitions:
            f.seek(offset)
            partition_data = f.read(size)
            output_path = os.path.join(output_folder, f"{name}.bin")
            with open(output_path, 'wb') as partition_file:
                partition_file.write(partition_data)
            print(f"Extracted {name} to {output_path}")

def main():
    file_path = 'example.bin'
    start_offset = 0x0000
    end_offset = 0x0000
    output_folder = 'partitions'
    partition_table_data = read_partition_table(file_path, start_offset, end_offset)
    partitions = parse_partition_table(partition_table_data)
    extract_partitions(file_path, partitions, output_folder)

if __name__ == "__main__":
    main()
