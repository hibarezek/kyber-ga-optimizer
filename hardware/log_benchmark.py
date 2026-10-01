"""
log_benchmark.py -- capture a full 1000-iteration benchmark run to a file.

Usage:
    python log_benchmark.py baseline_run1.log
    python log_benchmark.py P1_run1.log

It just needs one argument: the name of the file to save this run's output to.
Run it AFTER you've flashed the *_n1000.bin file and the board is back in
run mode (BOOT0 off 3V3, freshly unplugged/replugged), same as always.

What it does:
  - Opens COM3 at 38400 baud (same settings you've been using).
  - Writes every line the board sends straight to the log file, live.
  - Also prints a "." to your terminal every 50 lines, just so you can see
    it's alive without flooding your screen with 1000 iterations of text.
  - Automatically stops and closes the file as soon as it sees the "#"
    line the firmware prints after the very last iteration.
  - Should take roughly 2.5-3 minutes total for 1000 iterations. If it's
    been sitting for much longer than that with no dots appearing, something's
    wrong (check the board/wiring) -- Ctrl+C to stop safely either way.

When it finishes it'll print "Done -- saved N lines to <file>". Upload that
file back to me and I'll take it from there -- no need to open or read
through it yourself.
"""
import sys
import serial

PORT = "COM3"
BAUD = 38400

def main():
    if len(sys.argv) != 2:
        print("Usage: python log_benchmark.py <output_filename.log>")
        sys.exit(1)

    outfile = sys.argv[1]
    print(f"Opening {PORT} at {BAUD} baud...")
    ser = serial.Serial(PORT, BAUD, timeout=5)

    count = 0
    with open(outfile, "w", encoding="utf-8") as f:
        print("Listening. Waiting for the board's output (reset it now if you haven't)...")
        while True:
            raw = ser.readline()
            if not raw:
                # 5s with nothing at all -- just keep waiting, don't assume it's dead
                continue
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            f.write(line + "\n")
            f.flush()
            count += 1
            if count % 50 == 0:
                print(".", end="", flush=True)
            if line.strip() == "#":
                print(f"\nSaw the end-of-run marker. Done -- saved {count} lines to {outfile}")
                break

    ser.close()

if __name__ == "__main__":
    main()
