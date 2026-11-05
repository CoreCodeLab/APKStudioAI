import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

def main():
    """Main entry point - delegates to scanner CLI or GUI."""
    import argparse

    parser = argparse.ArgumentParser(description="APKStudioAI 2.1 - Android Malware Analyzer")
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument("--batch", help="Batch scan directory")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")

    args = parser.parse_args()

    # Launch GUI if no args or --gui specified
    if not args.apk and not args.batch and (args.gui or len(sys.argv) == 1):
        import tkinter as tk
        from gui import APKStudioGUI
        root = tk.Tk()
        APKStudioGUI(root, Path(__file__).resolve().parent)
        root.mainloop()
        return

    # Load config
    config = {}
    if args.config and Path(args.config).exists():
        with open(args.config) as f:
            config = json.load(f)

    # Progress callback
    def progress(stage, percent, message):
        print(f"[{percent:3d}%] {stage}: {message}")

    from core.scanner import APKScanner, format_text_output
    scanner = APKScanner(config, progress_callback=progress)

    if args.batch:
        results = scanner.batch_scan(args.batch, no_ai=args.no_ai)
        output_data = {"batch_results": results}
    elif args.apk:
        result = scanner.scan(args.apk, no_ai=args.no_ai)
        output_data = result
    else:
        parser.print_help()
        return

    # Output
    if args.json:
        output = json.dumps(output_data, indent=2, default=str)
    else:
        output = format_text_output(output_data)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Results saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
