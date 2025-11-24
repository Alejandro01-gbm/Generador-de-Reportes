import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


class AppView(ttk.Frame):
    """Interfaz gráfica mejorada del normalizador y generador de reportes SOC."""
    SUPPORTED_EXTENSIONS = {".txt", ".log", ".csv", ".jsonl", ".json"}

    def __init__(self, root: tk.Misc):
        super().__init__(root)
        self.root = root
        self.controller = None
        self.root.title("Generador de Reportes SOC")
        self.root.geometry("1200x750")
        self.root.minsize(900, 600)
        
        # Configurar estilos
        self._setup_styles()
        self._build()
        self.pack(fill=tk.BOTH, expand=True)

    def _setup_styles(self):
        """Configurar estilos personalizados"""
        style = ttk.Style()
        
        # Estilo para botón principal
        style.configure('Primary.TButton', font=('Segoe UI', 10, 'bold'))
        
        # Estilo para frame de drop
        style.configure('Drop.TFrame', relief=tk.SOLID, borderwidth=2)

    def _build(self):
        # Container principal con padding
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Panel superior dividido
        top = ttk.PanedWindow(main_container, orient=tk.HORIZONTAL)
        top.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # ==================== PANEL IZQUIERDO ====================
        left = ttk.Frame(top)
        top.add(left, weight=7)
        
        # Header con contador
        header_frame = ttk.Frame(left)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            header_frame, 
            text="📁 Archivos de Log", 
            font=("Segoe UI", 13, "bold")
        ).pack(side=tk.LEFT)
        
        self.file_count_label = ttk.Label(
            header_frame,
            text="(0 archivos)",
            font=("Segoe UI", 9),
            foreground="#666"
        )
        self.file_count_label.pack(side=tk.LEFT, padx=(8, 0))

        # Zona drag & drop mejorada
        self.drop_frame = tk.Frame(
            left, 
            relief=tk.GROOVE, 
            borderwidth=2,
            bg="#f0f4f8",
            height=120
        )
        self.drop_frame.pack(fill=tk.X, expand=False, pady=(0, 12))
        self.drop_frame.pack_propagate(False)  # Mantener altura fija
        
        drop_content = tk.Frame(self.drop_frame, bg="#f0f4f8")
        drop_content.pack(expand=True)
        
        # Contenedor horizontal para ícono y texto
        content_row = tk.Frame(drop_content, bg="#f0f4f8")
        content_row.pack(expand=True)
        
        # Ícono grande
        icon_label = tk.Label(
            content_row,
            text="📤",
            font=("Segoe UI", 28),
            bg="#f0f4f8"
        )
        icon_label.pack(side=tk.LEFT, padx=(0, 12))
        
        # Textos a la derecha
        text_container = tk.Frame(content_row, bg="#f0f4f8")
        text_container.pack(side=tk.LEFT)
        
        self.drop_label = tk.Label(
            text_container,
            text="Arrastra tus archivos de logs aquí",
            foreground="#2c3e50",
            font=("Segoe UI", 11, "bold"),
            bg="#f0f4f8",
            justify="left",
            anchor="w"
        )
        self.drop_label.pack(anchor="w")
        
        tk.Label(
            text_container,
            text="o haz clic en 'Añadir archivos' para seleccionarlos",
            foreground="#5a6c7d",
            font=("Segoe UI", 9),
            bg="#f0f4f8",
            justify="left",
            anchor="w"
        ).pack(anchor="w", pady=(2, 4))
        
        # Extensiones soportadas
        tk.Label(
            text_container,
            text="Formatos: .txt, .log, .csv, .json, .jsonl",
            foreground="#7f8c8d",
            font=("Segoe UI", 8),
            bg="#f0f4f8",
            justify="left",
            anchor="w"
        ).pack(anchor="w")

        # Tabla de archivos mejorada
        ttk.Label(
            left, 
            text="Archivos cargados:", 
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", pady=(8, 4))
        
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbars
        yscroll = ttk.Scrollbar(tree_frame)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        xscroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)

        self.file_tree = ttk.Treeview(
            tree_frame,
            columns=("Estado", "Tipo", "Ruta"),
            show="tree headings",
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set,
            height=10
        )
        yscroll.config(command=self.file_tree.yview)
        xscroll.config(command=self.file_tree.xview)
        
        self.file_tree.column("#0", width=220, anchor="w")
        self.file_tree.heading("#0", text="Nombre")
        self.file_tree.column("Estado", width=80, anchor="center")
        self.file_tree.heading("Estado", text="Estado")
        self.file_tree.column("Tipo", width=100, anchor="center")
        self.file_tree.heading("Tipo", text="Tipo")
        self.file_tree.column("Ruta", width=400, anchor="w")
        self.file_tree.heading("Ruta", text="Ruta")
        self.file_tree.pack(fill=tk.BOTH, expand=True)

        # Botones de acción
        btns = ttk.Frame(left)
        btns.pack(fill=tk.X, pady=(8, 0))
        
        ttk.Button(
            btns, 
            text="➕ Añadir archivos", 
            command=self._on_browse
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            btns, 
            text="✖ Quitar seleccionados", 
            command=self._on_remove
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btns, 
            text="🗑️ Limpiar todo", 
            command=self._on_clear
        ).pack(side=tk.LEFT, padx=5)

        # ==================== PANEL DERECHO ====================
        right = ttk.Frame(top, padding=10)
        top.add(right, weight=3)
        
        # Card de rutas de salida
        output_card = ttk.LabelFrame(
            right, 
            text=" 💾 Rutas de Salida ", 
            padding=12
        )
        output_card.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(output_card, text="CSV combinado:").pack(anchor="w", pady=(0, 2))
        row_csv = ttk.Frame(output_card)
        row_csv.pack(fill=tk.X, pady=(0, 10))
        self.csv_path = tk.StringVar(value="combined.csv")
        ttk.Entry(row_csv, textvariable=self.csv_path).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5)
        )
        ttk.Button(row_csv, text="📂", width=3, command=self._browse_csv).pack(side=tk.LEFT)

        ttk.Label(output_card, text="Reporte (.docx):").pack(anchor="w", pady=(0, 2))
        row_docx = ttk.Frame(output_card)
        row_docx.pack(fill=tk.X)
        self.docx_path = tk.StringVar(value="Reporte_Borrador.docx")
        ttk.Entry(row_docx, textvariable=self.docx_path).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5)
        )
        ttk.Button(row_docx, text="📂", width=3, command=self._browse_docx).pack(side=tk.LEFT)

        # Card de parámetros
        params_card = ttk.LabelFrame(
            right, 
            text="Parámetros del Reporte ", 
            padding=12
        )
        params_card.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(params_card, text="No de alerta:").pack(anchor="w", pady=(0, 2))
        self.alert_no = tk.StringVar()
        ttk.Entry(params_card, textvariable=self.alert_no).pack(fill=tk.X, pady=(0, 8))

        ttk.Label(params_card, text="Criticidad:").pack(anchor="w", pady=(0, 2))
        self.criticality = tk.StringVar()
        ttk.Combobox(
            params_card, 
            textvariable=self.criticality,
            values=["", "Informativa", "Baja", "Media", "Alta", "Crítica"],
            state="readonly"
        ).pack(fill=tk.X, pady=(0, 8))

        ttk.Label(params_card, text="Reportado por:").pack(anchor="w", pady=(0, 2))
        self.reported_by = tk.StringVar()
        ttk.Entry(params_card, textvariable=self.reported_by).pack(fill=tk.X)

        # Botones de acción principales
        action_frame = ttk.Frame(right)
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.btn_report = ttk.Button(
            action_frame,
            text="▶ Generar Reporte",
            style='Primary.TButton',
            command=self._on_build_all
        )
        self.btn_report.pack(fill=tk.X, ipady=8)

        ttk.Button(
            action_frame, 
            text="📂 Abrir carpeta de salida", 
            command=self._on_open_folder
        ).pack(fill=tk.X, pady=(8, 0))

        # Indicador de progreso (en el panel derecho)
        self.progress_frame = ttk.Frame(right)
        self.progress_label = ttk.Label(
            self.progress_frame,
            text="Procesando...",
            font=("Segoe UI", 9)
        )
        self.progress_label.pack(pady=(0, 5))
        self.progress = ttk.Progressbar(
            self.progress_frame,
            mode="indeterminate",
            length=200
        )
        self.progress.pack(fill=tk.X)

        # ==================== PANEL INFERIOR: LOGS ====================
        bottom = ttk.LabelFrame(
            main_container, 
            text=" 📋 Registro de eventos ", 
            padding=8
        )
        bottom.pack(fill=tk.BOTH, expand=True, pady=(0, 0))
        
        # Toolbar de logs
        log_toolbar = ttk.Frame(bottom)
        log_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(
            log_toolbar,
            text="🗑️ Limpiar registro",
            command=self._clear_log
        ).pack(side=tk.RIGHT)
        
        self.log_text = scrolledtext.ScrolledText(
            bottom,
            height=12,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Consolas", 9),
            bg="#f8f9fa"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configurar tags para niveles de log
        self.log_text.tag_config("INFO", foreground="#0066cc")
        self.log_text.tag_config("WARNING", foreground="#ff8800")
        self.log_text.tag_config("ERROR", foreground="#cc0000")
        self.log_text.tag_config("SUCCESS", foreground="#00aa00")

        # ==================== BARRA DE ESTADO ====================
        status_frame = ttk.Frame(main_container)
        status_frame.pack(fill=tk.X, pady=(8, 0))
        
        self.status_var = tk.StringVar(value="✓ Listo")
        status_label = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            padding=(5, 2)
        )
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # ------------------- Métodos auxiliares -------------------
    def _clear_log(self):
        """Limpiar el área de logs"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def set_controller(self, controller):
        self.controller = controller
        controller.bind_view()

    def _on_browse(self): self.controller.browse_files()
    def _on_remove(self): self.controller.remove_selected()
    def _on_clear(self): self.controller.clear_list()
    def _on_build_all(self): self.controller.run_build_all()
    def _on_open_folder(self): self.controller.open_output_folder()

    def _browse_csv(self):
        f = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="combined.csv"
        )
        if f: self.csv_path.set(f)

    def _browse_docx(self):
        f = filedialog.asksaveasfilename(
            defaultextension=".docx",
            filetypes=[("Word files", "*.docx")],
            initialfile="Reporte_Borrador.docx"
        )
        if f: self.docx_path.set(f)

    def refresh_files(self, items):
        """Actualizar lista de archivos con estado"""
        self.file_tree.delete(*self.file_tree.get_children())
        for it in items:
            # Determinar estado basado en tipo
            status = "✓ Válido" if it["type"] != "Desconocido" else "⚠ Revisar"
            self.file_tree.insert(
                "", "end",
                text=it["name"],
                values=(status, it["type"], it["path"])
            )
        
        # Actualizar contador
        count = len(items)
        self.file_count_label.config(
            text=f"({count} archivo{'s' if count != 1 else ''})"
        )

    def start_progress(self, interval_ms: int = 75):
        """Iniciar indicador de progreso"""
        self.progress_frame.pack(fill=tk.X, pady=(10, 0))
        self.progress['value'] = 0
        self.progress.start(interval_ms)
        self.btn_report.config(state=tk.DISABLED)

    def stop_progress(self):
        """Detener indicador de progreso"""
        self.progress.stop()
        self.progress['value'] = 0
        self.progress.update_idletasks()
        self.progress_frame.pack_forget()
        self.btn_report.config(state=tk.NORMAL)

    def set_status(self, text: str):
        """Actualizar barra de estado"""
        # Agregar ícono según el texto
        if "error" in text.lower():
            icon = "✗"
        elif "éxito" in text.lower() or "completo" in text.lower():
            icon = "✓"
        elif "procesando" in text.lower():
            icon = "⏳"
        else:
            icon = "ℹ️"
        
        self.status_var.set(f"{icon} {text}")

    def append_log(self, line: str):
        """Agregar línea al log con formato"""
        self.log_text.config(state=tk.NORMAL)
        
        # Detectar nivel de log
        tag = None
        if "[INFO]" in line or "✓" in line:
            tag = "INFO"
        elif "[WARNING]" in line or "⚠" in line:
            tag = "WARNING"
        elif "[ERROR]" in line or "✗" in line:
            tag = "ERROR"
        elif "[SUCCESS]" in line or "Éxito" in line:
            tag = "SUCCESS"
        
        if tag:
            self.log_text.insert(tk.END, line, tag)
        else:
            self.log_text.insert(tk.END, line)
        
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def info(self, title, msg): messagebox.showinfo(title, msg)
    def warn(self, title, msg): messagebox.showwarning(title, msg)
    def error(self, title, msg): messagebox.showerror(title, msg)