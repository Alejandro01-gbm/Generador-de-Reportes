#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from report_generator.run import generate_report
import argparse

def main():
    ap = argparse.ArgumentParser(
        description="Generador de borrador de reporte SOC L1 desde logs unificados (combined CSV)"
    )
    ap.add_argument("--in", dest="combined_csv", required=True, help="Ruta al CSV unificado (combined)")
    ap.add_argument("--out", dest="outfile", default="Reporte_Borrador.docx", help="Ruta de salida .docx")
    ap.add_argument("--alert-id", dest="alert_id", default=None, help="No. de alerta (opcional)")
    ap.add_argument("--criticidad", dest="criticidad", default=None, help="Criticidad (opcional)")
    ap.add_argument("--reportado-por", dest="reportado_por", default=None, help="Nombre del analista (opcional)")
    args = ap.parse_args()

    generate_report(
        combined_csv=args.combined_csv,
        outfile=args.outfile,
        override={
            "No de alerta": args.alert_id,
            "Criticidad": args.criticidad,
            "Reportado por": args.reportado_por,
        }
    )

if __name__ == "__main__":
    main()
