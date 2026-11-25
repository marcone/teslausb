#!/usr/bin/env python3
import sys
import os
import struct
import hashlib
import urllib.parse

def main():
    qs = os.environ.get("QUERY_STRING", "")
    params = urllib.parse.parse_qs(qs)
    file_arg = params.get("file", [""])[0]
    
    if not file_arg:
        # Fallback if raw path is passed without 'file='
        first = qs.split("&")[0] if qs else ""
        if "TeslaCam" in first:
            file_arg = urllib.parse.unquote_plus(first)
        else:
            sys.stdout.write("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nMissing file argument\r\n")
            return

    # Clean path
    target_rel = file_arg.lstrip("/")
    # Prevent directory traversal
    if ".." in target_rel:
        sys.stdout.write("Status: 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nForbidden\r\n")
        return

    full_path = os.path.join("/var/www/html", target_rel)
    if not os.path.isfile(full_path):
        sys.stdout.write("Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\n")
        sys.stdout.write(f"File not found: {target_rel}\r\n")
        return

    cache_dir = "/tmp/sei_cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(target_rel.encode("utf-8")).hexdigest()
    cache_file = os.path.join(cache_dir, f"{cache_key}.bin")

    # If cached, serve directly
    if os.path.isfile(cache_file):
        try:
            with open(cache_file, "rb") as cf:
                data = cf.read()
            sys.stdout.write("Status: 200 OK\r\n")
            sys.stdout.write("Content-Type: application/octet-stream\r\n")
            sys.stdout.write(f"Content-Length: {len(data)}\r\n")
            sys.stdout.write("Access-Control-Allow-Origin: *\r\n\r\n")
            sys.stdout.flush()
            sys.stdout.buffer.write(data)
            return
        except Exception:
            pass

    # Extract SEI NAL units from MP4 mdat box
    sei_bytes = bytearray()
    try:
        with open(full_path, "rb") as f:
            while True:
                header = f.read(8)
                if len(header) < 8:
                    break
                size, btype = struct.unpack(">I4s", header)
                if btype == b"mdat":
                    break
                elif size == 1:
                    size64, = struct.unpack(">Q", f.read(8))
                    f.seek(size64 - 16, 1)
                else:
                    f.seek(size - 8, 1)
            data = f.read()

        pos = 0
        dlen = len(data)
        while pos + 4 <= dlen:
            nal_size, = struct.unpack(">I", data[pos:pos+4])
            pos += 4
            if nal_size < 2 or pos + nal_size > dlen:
                pos += max(nal_size, 0)
                continue
            # NAL unit type: (byte & 0x1F) == 6 (SEI) and payload_type == 5 (user_data_unregistered)
            if (data[pos] & 0x1F) == 6 and data[pos+1] == 5:
                sei_bytes.extend(struct.pack(">I", nal_size))
                sei_bytes.extend(data[pos:pos+nal_size])
            pos += nal_size

        # Write cache
        temp_cache = f"{cache_file}.tmp.{os.getpid()}"
        with open(temp_cache, "wb") as f_out:
            f_out.write(sei_bytes)
        os.replace(temp_cache, cache_file)

    except Exception as e:
        sys.stdout.write("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n")
        sys.stdout.write(f"Extraction error: {e}\r\n")
        return

    # Serve extracted binary
    sys.stdout.write("Status: 200 OK\r\n")
    sys.stdout.write("Content-Type: application/octet-stream\r\n")
    sys.stdout.write(f"Content-Length: {len(sei_bytes)}\r\n")
    sys.stdout.write("Access-Control-Allow-Origin: *\r\n\r\n")
    sys.stdout.flush()
    sys.stdout.buffer.write(sei_bytes)

if __name__ == "__main__":
    main()
