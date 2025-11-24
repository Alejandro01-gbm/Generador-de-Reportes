import tkinter as tk

try:
    from tkinterdnd2 import TkinterDnD
    DRAG_DROP = True
except Exception:
    DRAG_DROP = False
    print("Advertencia: tkinterdnd2 no instalado. Drag & drop deshabilitado.")

from gui_app.ui import AppView
from gui_app.controllers import AppController

def main():
    root = TkinterDnD.Tk() if DRAG_DROP else tk.Tk()
    view = AppView(root)
    controller = AppController(view, drag_drop_enabled=DRAG_DROP)
    view.set_controller(controller)
    root.mainloop()

if __name__ == "__main__":
    main()
