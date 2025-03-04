import sys

def split_bin_file_with_start_and_end(file_path, n):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        chunk_size = file_size // n
        remainder = file_size % n

        start = 0
        for i in range(n):
            end = start + chunk_size + (1 if i < remainder else 0)
            chunk_data = data[start:end]

            output_file = f"{file_path}.part{i+1}.{start}-{end}"
            with open(output_file, 'wb') as out_f:
                out_f.write(chunk_data)
            print(f"Generated: {output_file} (Start Byte: {start}, End Byte: {end})")
            start = end

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python split_bin.py <file_path> <number_of_parts>")
        sys.exit(1)
    file_path = sys.argv[1]
    try:
        n = int(sys.argv[2])
        if n <= 0:
            print("Error: n must be a positive integer greater than 0.")
            sys.exit(1)
    except ValueError:
        print("Error: The number of parts must be an integer.")
        sys.exit(1)
    split_bin_file_with_start_and_end(file_path, n)