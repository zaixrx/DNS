import argparse

def getchunksize(limit, index, chunk_size):
    if (index + chunk_size >= limit):
        chunk_size -= limit - (index + chunk_size)
    return chunk_size

def main():
    parser = argparse.ArgumentParser(description="Read a DNS packet and dump it in hex.")
    parser.add_argument("file", help="Path to the binary file (DNS packet)")
    parser.add_argument("--chunk_size", type=int, default=16, help="Number of bytes written per line -- 1 indexed")
    parser.add_argument("--offset", type=int, default=0, help="Offset (in bytes) to start reading from --- 0 indexed")
    args = parser.parse_args()

    try:
        with open(args.file, "rb") as f:
            f.seek(args.offset)
            data = f.read(512 - args.offset - 1)
    except FileNotFoundError:
        print(f"File not found: {args.file}")
        return
    except Exception as e:
        print(f"Error: {e}")
        return

    for i in range(0, len(data), args.chunk_size):
        dbyte = data[i:i+args.chunk_size]
        hex_bytes = " ".join(f"{byte:02x}" for byte in dbyte)
        print(f"{args.offset:03d} | {i:03d}: {hex_bytes}")

if __name__ == "__main__":
    main()

