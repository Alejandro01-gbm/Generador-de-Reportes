from normalizer.run import normalize_files
import argparse

def main():
    ap = argparse.ArgumentParser(
        description="Normalizador (Cisco ASA, Splunk CSV, Cisco Secure Endpoint AMP) -> CSV unificado"
    )
    ap.add_argument("--in", dest="inputs", action="append", required=True,
                    help="Ruta de entrada (puedes repetir --in varias veces)")
    ap.add_argument("--out", dest="out_csv", required=True,
                    help="Ruta del CSV de salida")
    args = ap.parse_args()
    normalize_files(args.inputs, args.out_csv)

if __name__ == "__main__":
    main()
