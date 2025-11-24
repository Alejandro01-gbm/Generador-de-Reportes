import os
import threading
from pathlib import Path
import tkinter as tk

# Drag & Drop opcional
try:
    from tkinterdnd2 import DND_FILES
except Exception:
    DND_FILES = None

from .utils import UILogHandler, call_on_main, ts_line
# Backends del proyecto 
from normalizer.run import normalize_files
from report_generator.run import generate_report


class AppController:
    TYPE_MAP = {
        ".txt": "Cisco ASA",
        ".log": "Cisco ASA",
        ".csv": "Splunk",
        ".jsonl": "Cisco Secure Endpoint",
        ".json": "Cisco Secure Endpoint",
    }
    SUPPORTED = {".txt", ".log", ".csv", ".jsonl", ".json"}

    def __init__(self, view, drag_drop_enabled: bool):
        self.view = view
        self.root = view.root
        self.drag_drop_enabled = drag_drop_enabled
        self.file_list: list[dict] = []
        self.current_operation: str | None = None

        # Logging hacia la UI
        import logging
        self.logger = logging.getLogger("GUI")
        self.logger.setLevel(logging.DEBUG)
        handler = UILogHandler(self.append_log)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S"))
        if not any(isinstance(h, UILogHandler) for h in self.logger.handlers):
            self.logger.addHandler(handler)

        self.append_log(ts_line("Aplicación iniciada.") + "\n")

    # ------------------- Drag & Drop -------------------
    def bind_view(self):
        if self.drag_drop_enabled and DND_FILES is not None:
            try:
                self.view.drop_frame.drop_target_register(DND_FILES)
                self.view.drop_frame.dnd_bind("<<Drop>>", self._on_drop)
            except Exception as e:
                self.append_log(ts_line(f"⚠ No se pudo registrar DnD: {e}") + "\n")

    def _on_drop(self, event):
        try:
            paths = list(self.root.tk.splitlist(event.data))
            self.add_files(paths)
        except Exception as e:
            self.append_log(ts_line(f"✗ Error en drop: {e}") + "\n")

    # ------------------- Helpers UI-safe -------------------
    def append_log(self, text: str):
        call_on_main(self.root, self.view.append_log, text)

    def set_status(self, text: str):
        call_on_main(self.root, self.view.set_status, text)

    def _disable_buttons(self):
        call_on_main(self.root, lambda: self.view.btn_report.config(state=tk.DISABLED))

    def _enable_buttons(self):
        call_on_main(self.root, lambda: self.view.btn_report.config(state=tk.NORMAL))

    def _progress_start(self):
        call_on_main(self.root, self.view.start_progress)

    def _progress_stop(self):
        call_on_main(self.root, self.view.stop_progress)

    # ------------------- Gestión de archivos -------------------
    def add_files(self, paths: list[str]):
        added = 0
        for p in paths:
            path = Path(p)
            if not path.exists():
                self.append_log(ts_line(f"⚠ No existe: {path}") + "\n")
                continue
            ext = path.suffix.lower()
            if ext not in self.SUPPORTED:
                self.view.warn("Extensión no soportada",
                               f"'{path.name}' no es compatible.\nSoportadas: {', '.join(sorted(self.SUPPORTED))}")
                continue
            if any(x["path"] == str(path) for x in self.file_list):
                self.append_log(ts_line(f"ℹ Ya en lista: {path.name}") + "\n")
                continue
            self.file_list.append({"name": path.name, "type": self.TYPE_MAP.get(ext, "Desconocido"), "path": str(path)})
            added += 1

        call_on_main(self.root, self.view.refresh_files, self.file_list)
        if added:
            self.append_log(ts_line(f"Se añadieron {added} archivo(s).") + "\n")

    def remove_selected(self):
        sel = self.view.file_tree.selection()
        if not sel:
            self.view.info("Sin selección", "Selecciona al menos un archivo.")
            return
        idxs = sorted((self.view.file_tree.index(i) for i in sel), reverse=True)
        for i in idxs:
            del self.file_list[i]
        self.view.refresh_files(self.file_list)
        self.append_log(ts_line(f"Se eliminaron {len(sel)} archivo(s).") + "\n")

    def clear_list(self):
        if not self.file_list:
            self.view.info("Lista vacía", "No hay archivos.")
            return
        from tkinter import messagebox
        if messagebox.askyesno("Confirmar", "¿Limpiar toda la lista?"):
            self.file_list.clear()
            self.view.refresh_files(self.file_list)
            self.append_log(ts_line("Lista limpiada.") + "\n")

    def browse_files(self):
        from tkinter import filedialog
        files = filedialog.askopenfilenames(
            title="Selecciona archivos de log",
            filetypes=[("Archivos soportados", "*.txt *.log *.csv *.jsonl *.json"),
                       ("Todos", "*.*")],
        )
        if files:
            self.add_files(list(files))

    # ------------------- Build All (normaliza + reporte) -------------------
    def run_build_all(self):
        if not self.file_list:
            self.view.warn("Sin archivos", "Añade al menos un archivo para generar el reporte.")
            return
        if self.current_operation:
            self.view.info("En ejecución", "Ya hay una operación en curso.")
            return

        out_csv = Path(self.view.csv_path.get())
        out_docx = Path(self.view.docx_path.get())
        try:
            out_csv.parent.mkdir(parents=True, exist_ok=True)
            out_docx.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.view.error("Error", f"No se pudieron crear directorios:\n{e}")
            return

        override = {}
        if self.view.alert_no.get():    override["No de alerta"] = self.view.alert_no.get()
        if self.view.criticality.get(): override["Criticidad"] = self.view.criticality.get()
        if self.view.reported_by.get(): override["Reportado por"] = self.view.reported_by.get()

        self.current_operation = "build_all"
        t = threading.Thread(
            target=self._build_all_worker,
            args=([x["path"] for x in self.file_list], str(out_csv), str(out_docx), override),
            daemon=True,
        )
        t.start()

    def _needs_normalize(self, files: list[str], csv_path: Path) -> bool:
        """True si el CSV no existe o está más viejo que alguno de los insumos."""
        if not csv_path.exists():
            return True
        csv_mtime = csv_path.stat().st_mtime
        try:
            return any(Path(f).stat().st_mtime > csv_mtime for f in files)
        except Exception:
            # Ante duda, se normaliza
            return True

    def _build_all_worker(self, files: list[str], out_csv: str, out_docx: str, override: dict):
        self._disable_buttons(); self.set_status("⏳ Preparando…"); self._progress_start()
        try:
            csv_path = Path(out_csv)

            # 1) Normalización si hace falta (si prefieres forzar siempre, elimina el if)
            if self._needs_normalize(files, csv_path):
                self.append_log(ts_line("Iniciando normalización…") + "\n")
                normalize_files(files, out_csv)
                self.append_log(ts_line(f"✓ CSV generado: {out_csv}") + "\n")
            else:
                self.append_log(ts_line("CSV actualizado; se omite normalización.") + "\n")

            # 2) Generación de reporte
            self.append_log(ts_line("Generando reporte DOCX…") + "\n")
            generate_report(out_csv, out_docx, override if override else None)
            self.append_log(ts_line(f"✓ Reporte generado: {out_docx}") + "\n")
            self.set_status(f"✓ Reporte en: {out_docx}")
            self.view.info("Éxito", f"Reporte generado en:\n{out_docx}")
        except Exception as e:
            self.append_log(ts_line(f"✗ Error en build_all: {e}") + "\n")
            self.set_status("✗ Error")
            self.view.error("Error", f"Ocurrió un error:\n{e}")
        finally:
            self._progress_stop(); self._enable_buttons(); self.current_operation = None

    # ------------------- Utilidades -------------------
    def open_output_folder(self):
        folder = Path(self.view.docx_path.get()).parent
        if not folder.exists():
            self.view.warn("Carpeta no existe", "Primero genera el reporte.")
            return
        try:
            os.startfile(folder)  # Windows
        except AttributeError:
            import subprocess, platform
            subprocess.Popen(["open" if platform.system() == "Darwin" else "xdg-open", str(folder)])
