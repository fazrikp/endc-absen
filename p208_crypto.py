import argparse
import os

from crp_tool import analyze_crp, process_file


def main():
    parser = argparse.ArgumentParser(description="P208 CRP Encrypt/Decrypt Tool")
    parser.add_argument("input", help="File input")
    parser.add_argument("output", help="File output")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], default="decrypt")
    parser.add_argument("--method", choices=["auto", "aes", "xor"], default="auto")
    parser.add_argument("--key", help="Key AES (auto uses myKey123 when omitted)")
    parser.add_argument("--xor-key", type=int, help="Key XOR (0-255)")
    parser.add_argument("--analyze", action="store_true", help="Hanya analisis file .crp")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ File tidak ditemukan: {args.input}")
        raise SystemExit(1)

    if args.analyze:
        analyze_crp(args.input)
        return

    process_file(
        input_path=args.input,
        output_path=args.output,
        mode=args.mode,
        method=args.method,
        key=args.key,
        xor_key=args.xor_key,
    )


if __name__ == "__main__":
    main()