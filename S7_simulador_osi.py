import sys
import os
import time
import base64
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# ==============================================================================
# CONFIGURACIÓN TÉCNICA DE SEÑALES (MÓDULO DE SOCKETS Y MANEJADORES POSIX)
# ==============================================================================
try:
    import signal
    import fcntl
    HAS_POSIX_SIGNALS = True
except ImportError:
    HAS_POSIX_SIGNALS = False


class SocketSignalEmulator:
    """
    Gestiona la simulación de señales de sockets para la arquitectura del simulador.
    Soporta eventos asíncronos (SIGURG, SIGIO) y síncronos (SIGPIPE, EINTR).
    """
    def __init__(self, log_callback):
        self.log_callback = log_callback
        self.pid = os.getpid()
        self.fasync_enabled = False
        self.owner_pid = None

    def set_owner(self, pid):
        self.owner_pid = pid
        self.log_callback(f"[SIGNAL API] fcntl(fd, F_SETOWN, {pid}) -> Propietario configurado.", "SIGNAL")

    def set_fasync(self, enabled=True):
        self.fasync_enabled = enabled
        flag_str = "FASYNC (ON)" if enabled else "FASYNC (OFF)"
        self.log_callback(f"[SIGNAL API] fcntl(fd, F_SETFL, {flag_str}) -> Notificación I/O asíncrona activada.", "SIGNAL")

    def trigger_sigurg(self):
        msg = f"[SEÑAL OOB] SIGURG entregada al proceso PID={self.owner_pid or self.pid} (Datos fuera de banda recibidos en socket)."
        self.log_callback(msg, "WARNING")

    def trigger_sigio(self):
        if self.fasync_enabled:
            msg = f"[SEÑAL I/O] SIGIO entregada al proceso PID={self.owner_pid or self.pid} (I/O asíncrona disponible)."
            self.log_callback(msg, "SUCCESS")
        else:
            msg = "[SEÑAL I/O] Evento I/O omitido: Bandera FASYNC no habilitada en el socket."
            self.log_callback(msg, "ERROR")

    def trigger_sigpipe(self):
        msg = "[SEÑAL SÍNCRONA] SIGPIPE capturada: Intento de escritura en socket cerrado/roto. Invocando errno [EPIPE]."
        self.log_callback(msg, "ERROR")

    def trigger_eintr(self):
        msg = "[SISTEMA INTERRUMPIDO] API de Socket bloqueada (read/recv/select) interrumpida por señal. Devolviendo errno [EINTR]."
        self.log_callback(msg, "WARNING")


# ==============================================================================
# ESTRUCTURA DE CAPAS Y MODELO OSI
# ==============================================================================
OSI_LAYERS_SENDER = [
    ("7. Aplicación", "APL", "Datos puros de la aplicación"),
    ("6. Presentación", "PRE", "Formateo/Codificación Base64"),
    ("5. Sesión", "SES", "Sincronización y control de diálogo"),
    ("4. Transporte", "TRA", "Header TCP/UDP (Puertos Origen/Destino)"),
    ("3. Red", "RED", "Header IP (Direcciones IP Origen/Destino)"),
    ("2. Enlace de Datos", "ENL", "Header Ethernet/MAC (Tramas + CRC)"),
    ("1. Física", "FIS", "Cadena de Bits / Pulsos Eléctricos")
]

OSI_LAYERS_RECEIVER = list(reversed(OSI_LAYERS_SENDER))

# --------------------------------------------------------------------
# Prefijos/sufijos de cabecera por capa. Se usan tanto para ENCAPSULAR
# (envolver el PDU) como para DESENCAPSULAR (retirar exactamente lo que
# se agregó), de modo que el proceso es real y reversible, no decorativo.
# --------------------------------------------------------------------
LAYER_WRAPPERS = {
    "APL": ("[DATA: ", "]"),
    "SES": ("[SESSION_ID_9921: ", "]"),
    "TRA": ("[TCP_HDR: Port 80->443 | ", "]"),
    "RED": ("[IP_HDR: 192.168.1.10->192.168.1.20 | ", "]"),
    "ENL": ("[ETH_HDR: MAC_A->MAC_B | ", " | FCS_CRC32]"),
}


# ==============================================================================
# FUNCIONES DE CODIFICACIÓN BASE64 (CAPA DE PRESENTACIÓN)
# ==============================================================================
def codificar_base64(texto):
    """
    Nombre: codificar_base64
    Objetivo: Convertir una cadena de texto a su representación en Base64,
              simulando el formateo/codificación de datos que realiza la
              capa de Presentación del Modelo OSI antes de enviarlos.
    Parámetros: texto (str) - cadena a codificar.
    Resultado: cadena en Base64 (str).
    Parte del proceso OSI: Capa 6 - Presentación (Encapsulamiento).
    """
    return base64.b64encode(texto.encode("utf-8")).decode("utf-8")


def decodificar_base64(texto_b64):
    """
    Nombre: decodificar_base64
    Objetivo: Revertir la codificación Base64 aplicada en el emisor,
              recuperando el texto original que traía la PDU.
    Parámetros: texto_b64 (str) - cadena codificada en Base64.
    Resultado: cadena de texto original (str).
    Parte del proceso OSI: Capa 6 - Presentación (Desencapsulamiento).
    """
    return base64.b64decode(texto_b64.encode("utf-8")).decode("utf-8")


# ==============================================================================
# FUNCIONES DE ENCAPSULAMIENTO / DESENCAPSULAMIENTO (LÓGICA REAL, NO DECORATIVA)
# ==============================================================================
def encapsular(mensaje):
    """
    Nombre: encapsular
    Objetivo: Aplicar, capa por capa (7 -> 1), las cabeceras correspondientes
              al mensaje original, incluyendo la codificación Base64 en la
              capa de Presentación, hasta obtener la PDU final lista para
              transmitir por el canal.
    Parámetros: mensaje (str) - payload original de la capa de Aplicación.
    Resultado: tupla (pdu_final, trazas) donde trazas es un diccionario con
               el estado del PDU luego de procesar cada capa (para mostrarlo
               en el Inspector de PDU del simulador).
    Parte del proceso OSI: Capas 7 a 1 (Encapsulamiento completo, PC-A).
    """
    trazas = {}

    # Capa 7 - Aplicación
    pdu = f"{LAYER_WRAPPERS['APL'][0]}{mensaje}{LAYER_WRAPPERS['APL'][1]}"
    trazas["APL"] = pdu

    # Capa 6 - Presentación: codificación Base64 real del PDU completo
    pdu_b64 = codificar_base64(pdu)
    pdu = f"[ENCODING_BASE64: {pdu_b64}]"
    trazas["PRE"] = pdu

    # Capa 5 - Sesión
    pdu = f"{LAYER_WRAPPERS['SES'][0]}{pdu}{LAYER_WRAPPERS['SES'][1]}"
    trazas["SES"] = pdu

    # Capa 4 - Transporte
    pdu = f"{LAYER_WRAPPERS['TRA'][0]}{pdu}{LAYER_WRAPPERS['TRA'][1]}"
    trazas["TRA"] = pdu

    # Capa 3 - Red
    pdu = f"{LAYER_WRAPPERS['RED'][0]}{pdu}{LAYER_WRAPPERS['RED'][1]}"
    trazas["RED"] = pdu

    # Capa 2 - Enlace de Datos
    pdu = f"{LAYER_WRAPPERS['ENL'][0]}{pdu}{LAYER_WRAPPERS['ENL'][1]}"
    trazas["ENL"] = pdu

    # Capa 1 - Física: representación en bits de la TRAMA REAL
    # generada por la capa de Enlace. Esto hace que la representación
    # física corresponda con la PDU que realmente sale del encapsulamiento.
    bits_trama = "".join(format(b, '08b') for b in pdu.encode("utf-8")[:24])
    if len(pdu.encode("utf-8")) > 24:
        bits_trama += "..."
    trazas["FIS"] = bits_trama

    return pdu, trazas


def desencapsular(pdu_final):
    """
    Nombre: desencapsular
    Objetivo: Revertir, capa por capa (1 -> 7), exactamente las cabeceras
              agregadas en el emisor -incluyendo la decodificación Base64
              en Presentación- hasta reconstruir el mensaje original.
    Parámetros: pdu_final (str) - PDU completa recibida desde el canal.
    Resultado: tupla (mensaje_original, trazas) donde trazas es un
               diccionario con el estado del PDU luego de procesar cada
               capa en el receptor.
    Parte del proceso OSI: Capas 1 a 7 (Desencapsulamiento completo, PC-B).
    """
    trazas = {}
    pdu = pdu_final
    trazas["FIS"] = "Trama recibida en el medio físico."

    # Capa 2 - Enlace de Datos
    pdu = pdu.removeprefix(LAYER_WRAPPERS["ENL"][0]).removesuffix(LAYER_WRAPPERS["ENL"][1])
    trazas["ENL"] = pdu

    # Capa 3 - Red
    pdu = pdu.removeprefix(LAYER_WRAPPERS["RED"][0]).removesuffix(LAYER_WRAPPERS["RED"][1])
    trazas["RED"] = pdu

    # Capa 4 - Transporte
    pdu = pdu.removeprefix(LAYER_WRAPPERS["TRA"][0]).removesuffix(LAYER_WRAPPERS["TRA"][1])
    trazas["TRA"] = pdu

    # Capa 5 - Sesión
    pdu = pdu.removeprefix(LAYER_WRAPPERS["SES"][0]).removesuffix(LAYER_WRAPPERS["SES"][1])
    trazas["SES"] = pdu

    # Capa 6 - Presentación: decodificación Base64 real
    pdu_b64 = pdu.removeprefix("[ENCODING_BASE64: ").removesuffix("]")
    pdu = decodificar_base64(pdu_b64)
    trazas["PRE"] = pdu

    # Capa 7 - Aplicación
    mensaje_original = pdu.removeprefix(LAYER_WRAPPERS["APL"][0]).removesuffix(LAYER_WRAPPERS["APL"][1])
    trazas["APL"] = mensaje_original

    return mensaje_original, trazas


def transmitir(mensaje):
    """
    Nombre: transmitir
    Objetivo: Función principal del simulador. Orquesta el proceso completo
              de comunicación de datos entre PC-A y PC-B: aplica el
              encapsulamiento en el emisor, simula el paso por el canal y
              ejecuta el desencapsulamiento en el receptor, verificando que
              el mensaje recuperado sea idéntico al original.
    Parámetros: mensaje (str) - texto que el usuario desea transmitir.
    Resultado: tupla (mensaje_reconstruido, exito, trazas_enc, trazas_desenc)
               donde exito (bool) indica si el mensaje recuperado coincide
               exactamente con el original.
    Parte del proceso OSI: Todo el proceso (Encapsulamiento + Canal +
                            Desencapsulamiento).
    """
    pdu_final, trazas_enc = encapsular(mensaje)
    mensaje_reconstruido, trazas_desenc = desencapsular(pdu_final)
    exito = (mensaje_reconstruido == mensaje)
    return mensaje_reconstruido, exito, trazas_enc, trazas_desenc


# ==============================================================================
# INTERFAZ GRÁFICA INTERACTIVA (TKINTER DARK THEME)
# ==============================================================================
class OSINetworkSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulador de Comunicación de Datos - Modelo OSI | UNEMI")
        self.root.geometry("1280x820")
        self.root.configure(bg="#0F172A")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.setup_custom_styles()

        self.signal_emulator = SocketSignalEmulator(self.log)

        self.data_input_var = tk.StringVar(value="Datos de Evaluación UNEMI 2026")
        self.speed_var = tk.DoubleVar(value=0.5)
        self.is_simulating = False

        self.create_header()
        self.create_technical_note()
        self.create_control_panel()
        self.create_simulation_canvas_panel()
        self.create_signal_and_pdu_panel()
        self.create_log_console()

    def setup_custom_styles(self):
        self.style.configure("TFrame", background="#0F172A")
        self.style.configure("Card.TFrame", background="#1E293B", relief="flat")
        self.style.configure("Header.TLabel", background="#1E293B", foreground="#F8FAFC", font=("Helvetica", 14, "bold"))
        self.style.configure("SubHeader.TLabel", background="#0F172A", foreground="#94A3B8", font=("Helvetica", 9))
        self.style.configure("Primary.TButton", background="#2563EB", foreground="#FFFFFF", font=("Helvetica", 10, "bold"))
        self.style.map("Primary.TButton", background=[("active", "#1D4ED8")])
        self.style.configure("Reset.TButton", background="#475569", foreground="#FFFFFF", font=("Helvetica", 10, "bold"))
        self.style.map("Reset.TButton", background=[("active", "#334155")])

    def create_header(self):
        header_frame = tk.Frame(self.root, bg="#1E293B", height=60, bd=0)
        header_frame.pack(fill="x", side="top", padx=10, pady=(10, 5))

        tk.Label(
            header_frame,
            text="UNIVERSIDAD ESTATAL DE MILAGRO - INGENIERÍA EN TIC",
            font=("Helvetica", 14, "bold"), bg="#1E293B", fg="#F8FAFC"
        ).pack(anchor="w", padx=15, pady=(8, 0))

        tk.Label(
            header_frame,
            text="Simulador Interactivo de Encapsulamiento/Desencapsulamiento OSI & Manejo de Señales en Sockets",
            font=("Helvetica", 9), bg="#1E293B", fg="#94A3B8"
        ).pack(anchor="w", padx=15, pady=(0, 8))

    def create_technical_note(self):
        note_frame = tk.Frame(self.root, bg="#0B1220", bd=1, relief="solid",
                               highlightbackground="#334155", highlightthickness=1)
        note_frame.pack(fill="x", padx=10, pady=(0, 5))

        nota_texto = (
            "NOTA TÉCNICA: En el Emisor (PC-A) el modelo OSI se recorre de la capa 7 a la 1, "
            "porque describe el proceso de ENCAPSULAMIENTO: la Aplicación genera el mensaje y cada "
            "capa inferior le añade su propia cabecera (incluyendo la codificación Base64 en "
            "Presentación) hasta convertirlo en bits sobre el medio físico. En el Receptor (PC-B) el "
            "recorrido es inverso, de la capa 1 a la 7, porque es el proceso de DESENCAPSULAMIENTO: "
            "cada capa retira su cabecera correspondiente -y se decodifica el Base64- hasta "
            "reconstruir el mensaje original en la Aplicación."
        )

        tk.Label(
            note_frame, text=nota_texto, font=("Helvetica", 9, "italic"),
            bg="#0B1220", fg="#CBD5E1", wraplength=1220, justify="left", padx=12, pady=8
        ).pack(fill="x")

    def create_control_panel(self):
        control_frame = tk.Frame(self.root, bg="#1E293B", bd=1, relief="solid")
        control_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(control_frame, text="Mensaje / Payload:", font=("Helvetica", 10, "bold"), bg="#1E293B", fg="#CBD5E1").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        data_entry = tk.Entry(control_frame, textvariable=self.data_input_var, font=("Consolas", 10), width=35, bg="#0F172A", fg="#38BDF8", insertbackground="white")
        data_entry.grid(row=0, column=1, padx=5, pady=10)

        tk.Label(control_frame, text="Retardo (s):", font=("Helvetica", 10, "bold"), bg="#1E293B", fg="#CBD5E1").grid(row=0, column=2, padx=(15, 5), pady=10)
        speed_spin = tk.Spinbox(control_frame, from_=0.1, to=2.0, increment=0.1, textvariable=self.speed_var, width=5, font=("Helvetica", 10), bg="#0F172A", fg="#F8FAFC")
        speed_spin.grid(row=0, column=3, padx=5, pady=10)

        self.btn_send = tk.Button(control_frame, text="🚀 ENVIAR MENSAJE", font=("Helvetica", 10, "bold"), bg="#2563EB", fg="white", activebackground="#1D4ED8", activeforeground="white", command=self.start_simulation_thread)
        self.btn_send.grid(row=0, column=4, padx=15, pady=10)

        self.btn_reset = tk.Button(control_frame, text="🔄 RESETEAR", font=("Helvetica", 10, "bold"), bg="#475569", fg="white", activebackground="#334155", activeforeground="white", command=self.reset_simulation)
        self.btn_reset.grid(row=0, column=5, padx=5, pady=10)

    def create_simulation_canvas_panel(self):
        sim_container = tk.Frame(self.root, bg="#0F172A")
        sim_container.pack(fill="x", padx=10, pady=5)

        sender_box = tk.LabelFrame(sim_container, text=" TERMINAL EMISOR (PC-A / ENCAPSULAMIENTO) ", font=("Helvetica", 10, "bold"), bg="#1E293B", fg="#38BDF8", bd=1)
        sender_box.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.sender_widgets = {}
        for idx, (fullName, shortCode, desc) in enumerate(OSI_LAYERS_SENDER):
            f = tk.Frame(sender_box, bg="#0F172A", bd=1, relief="ridge")
            f.pack(fill="x", padx=10, pady=2)
            lbl_code = tk.Label(f, text=shortCode, font=("Consolas", 9, "bold"), bg="#334155", fg="#F8FAFC", width=6)
            lbl_code.pack(side="left", padx=2, pady=2)
            lbl_desc = tk.Label(f, text=fullName, font=("Helvetica", 9), bg="#0F172A", fg="#94A3B8")
            lbl_desc.pack(side="left", padx=10)
            self.sender_widgets[idx] = (f, lbl_code, lbl_desc)

        channel_box = tk.LabelFrame(sim_container, text=" CANAL M/M/1 ", font=("Helvetica", 9, "bold"), bg="#1E293B", fg="#F59E0B", bd=1)
        channel_box.pack(side="left", fill="both", padx=5)

        self.lbl_channel_arrow = tk.Label(channel_box, text="➔\n➔\n➔", font=("Helvetica", 16, "bold"), bg="#1E293B", fg="#64748B")
        self.lbl_channel_arrow.pack(expand=True, padx=15)
        self.lbl_channel_status = tk.Label(channel_box, text="IDLE", font=("Consolas", 8, "bold"), bg="#1E293B", fg="#94A3B8")
        self.lbl_channel_status.pack(pady=(0, 10))

        receiver_box = tk.LabelFrame(sim_container, text=" TERMINAL RECEPTOR (PC-B / DESENCAPSULAMIENTO) ", font=("Helvetica", 10, "bold"), bg="#1E293B", fg="#4ADE80", bd=1)
        receiver_box.pack(side="right", fill="both", expand=True, padx=(5, 0))

        self.receiver_widgets = {}
        for idx, (fullName, shortCode, desc) in enumerate(OSI_LAYERS_RECEIVER):
            f = tk.Frame(receiver_box, bg="#0F172A", bd=1, relief="ridge")
            f.pack(fill="x", padx=10, pady=2)
            lbl_code = tk.Label(f, text=shortCode, font=("Consolas", 9, "bold"), bg="#334155", fg="#F8FAFC", width=6)
            lbl_code.pack(side="left", padx=2, pady=2)
            lbl_desc = tk.Label(f, text=fullName, font=("Helvetica", 9), bg="#0F172A", fg="#94A3B8")
            lbl_desc.pack(side="left", padx=10)
            self.receiver_widgets[idx] = (f, lbl_code, lbl_desc)

    def create_signal_and_pdu_panel(self):
        middle_container = tk.Frame(self.root, bg="#0F172A")
        middle_container.pack(fill="x", padx=10, pady=5)

        pdu_box = tk.LabelFrame(middle_container, text=" INSPECTOR DE PDU & CABECERAS ", font=("Helvetica", 9, "bold"), bg="#1E293B", fg="#F8FAFC", bd=1)
        pdu_box.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.lbl_pdu_inspect = tk.Label(pdu_box, text="Esperando transmisión...", font=("Consolas", 9), bg="#0F172A", fg="#38BDF8", anchor="w", justify="left", padx=10, pady=8, wraplength=620)
        self.lbl_pdu_inspect.pack(fill="both", expand=True, padx=5, pady=5)

        sig_box = tk.LabelFrame(middle_container, text=" SIMULACIÓN DE SEÑALES DE SOCKETS (manual + automática) ", font=("Helvetica", 9, "bold"), bg="#1E293B", fg="#A855F7", bd=1)
        sig_box.pack(side="right", fill="both", expand=True, padx=(5, 0))

        btn_grid = tk.Frame(sig_box, bg="#1E293B")
        btn_grid.pack(pady=5)

        tk.Button(btn_grid, text="fcntl(F_SETOWN)", font=("Consolas", 8, "bold"), bg="#334155", fg="#38BDF8", command=lambda: self.signal_emulator.set_owner(os.getpid())).grid(row=0, column=0, padx=2, pady=2)
        tk.Button(btn_grid, text="fcntl(FASYNC)", font=("Consolas", 8, "bold"), bg="#334155", fg="#38BDF8", command=lambda: self.signal_emulator.set_fasync(True)).grid(row=0, column=1, padx=2, pady=2)
        tk.Button(btn_grid, text="Emite SIGURG", font=("Consolas", 8, "bold"), bg="#854D0E", fg="#FEF08A", command=self.signal_emulator.trigger_sigurg).grid(row=0, column=2, padx=2, pady=2)
        tk.Button(btn_grid, text="Emite SIGIO", font=("Consolas", 8, "bold"), bg="#166534", fg="#BBF7D0", command=self.signal_emulator.trigger_sigio).grid(row=1, column=0, padx=2, pady=2)
        tk.Button(btn_grid, text="Error SIGPIPE", font=("Consolas", 8, "bold"), bg="#991B1B", fg="#FECACA", command=self.signal_emulator.trigger_sigpipe).grid(row=1, column=1, padx=2, pady=2)
        tk.Button(btn_grid, text="Errno EINTR", font=("Consolas", 8, "bold"), bg="#9A3412", fg="#FFEDD5", command=self.signal_emulator.trigger_eintr).grid(row=1, column=2, padx=2, pady=2)

        tk.Label(sig_box, text="* Además de los botones manuales, el flujo de envío\n"
                               "  dispara F_SETOWN, FASYNC y SIGIO automáticamente.",
                 font=("Helvetica", 7, "italic"), bg="#1E293B", fg="#64748B", justify="left").pack(padx=5, pady=(0, 5))

    def create_log_console(self):
        log_box = tk.LabelFrame(self.root, text=" REGISTRO DE EVENTOS & CONSOLA DE TRANSMISIÓN ", font=("Helvetica", 9, "bold"), bg="#1E293B", fg="#F8FAFC", bd=1)
        log_box.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.txt_log = scrolledtext.ScrolledText(log_box, font=("Consolas", 9), bg="#090D16", fg="#F8FAFC", relief="flat")
        self.txt_log.pack(fill="both", expand=True, padx=5, pady=5)

        self.txt_log.tag_config("INFO", foreground="#CBD5E1")
        self.txt_log.tag_config("SUCCESS", foreground="#4ADE80")
        self.txt_log.tag_config("WARNING", foreground="#FACC15")
        self.txt_log.tag_config("ERROR", foreground="#F87171")
        self.txt_log.tag_config("SIGNAL", foreground="#C084FC")
        self.txt_log.tag_config("HEADER", foreground="#38BDF8", font=("Consolas", 9, "bold"))

    def log(self, message, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"

        def _update():
            self.txt_log.insert(tk.END, formatted_msg, level)
            self.txt_log.see(tk.END)

        self.root.after(0, _update)

    def start_simulation_thread(self):
        if self.is_simulating:
            return

        if not self.data_input_var.get().strip():
            self.signal_emulator.trigger_sigpipe()
            messagebox.showerror("Error de Socket", "Payload vacío: no se puede escribir en el socket (EPIPE).")
            return

        self.is_simulating = True
        self.btn_send.config(state="disabled", bg="#64748B")
        threading.Thread(target=self.run_simulation, daemon=True).start()

    def run_simulation(self):
        raw_data = self.data_input_var.get()
        delay = self.speed_var.get()

        self.log("================ START OSI TRANSMISSION ================", "HEADER")
        self.log(f"Iniciando emisor (PC-A). Payload de aplicación: '{raw_data}'")

        # Configuración del socket (F_SETOWN + FASYNC) antes de encapsular
        self.signal_emulator.set_owner(os.getpid())
        time.sleep(delay * 0.3)
        self.signal_emulator.set_fasync(True)
        time.sleep(delay * 0.3)

        # --------------------------------------------------------------
        # CORRECCIÓN: se llama a la función transmitir(), que internamente
        # ejecuta encapsular() y desencapsular() con lógica real (Base64
        # incluido), en vez de simular todo con texto decorativo inline.
        # --------------------------------------------------------------
        mensaje_reconstruido, exito, trazas_enc, trazas_desenc = transmitir(raw_data)

        # --- FASE 1: ENCAPSULAMIENTO (EMISOR PC-A), usando trazas_enc ---
        for idx, (fullName, shortCode, desc) in enumerate(OSI_LAYERS_SENDER):
            self.highlight_layer(self.sender_widgets, idx, active=True)
            pdu_mostrado = trazas_enc[shortCode]
            self.update_pdu_display(f"Capa {fullName}:\nPDU: {pdu_mostrado}")
            self.log(f"[PC-A] Capa {shortCode} procesada. Encapsulado: {pdu_mostrado}")
            time.sleep(delay)
            self.highlight_layer(self.sender_widgets, idx, active=False)

        # --- FASE 2: TRÁNSITO POR EL CANAL ---
        self.log("[CANAL M/M/1] Simulando el tránsito de la trama como bits por el medio físico...", "WARNING")
        self.lbl_channel_status.config(text="BUSY (TX)", fg="#F59E0B")
        self.lbl_channel_arrow.config(fg="#F59E0B")

        if delay >= 1.0:
            time.sleep(delay * 0.5)
            self.signal_emulator.trigger_eintr()

        time.sleep(delay * 1.5)
        self.lbl_channel_status.config(text="IDLE", fg="#94A3B8")
        self.lbl_channel_arrow.config(fg="#64748B")

        # --- FASE 3: DESENCAPSULAMIENTO (RECEPTOR PC-B), usando trazas_desenc ---
        self.log("[PC-B] Trama recibida en la interfaz física.", "SUCCESS")
        self.signal_emulator.trigger_sigio()
        self.log("[PC-B] Iniciando desencapsulamiento real (lectura 1 -> 7).", "SUCCESS")

        for idx, (fullName, shortCode, desc) in enumerate(OSI_LAYERS_RECEIVER):
            self.highlight_layer(self.receiver_widgets, idx, active=True)
            pdu_mostrado = trazas_desenc[shortCode]
            self.update_pdu_display(f"Capa {fullName} (Receptor):\nPDU tras retirar cabecera: {pdu_mostrado}")
            self.log(f"[PC-B] Capa {shortCode} desencapsulada -> {pdu_mostrado}")
            time.sleep(delay)
            self.highlight_layer(self.receiver_widgets, idx, active=False)

        self.update_pdu_display(f"Mensaje Reconstruido en PC-B:\n'{mensaje_reconstruido}'")

        if exito:
            self.log(f"[ÉXITO] transmitir() verificó que el mensaje coincide con el original: '{mensaje_reconstruido}'", "SUCCESS")
        else:
            self.log(f"[FALLO] El mensaje reconstruido NO coincide con el original.", "ERROR")

        self.log("================ END OSI TRANSMISSION ================", "HEADER")

        self.is_simulating = False
        self.root.after(0, lambda: self.btn_send.config(state="normal", bg="#2563EB"))

    def highlight_layer(self, layer_dict, idx, active=True):
        def _apply():
            frame, lbl_code, lbl_desc = layer_dict[idx]
            if active:
                frame.config(bg="#1E3A8A", bd=2, relief="solid")
                lbl_code.config(bg="#2563EB", fg="#FFFFFF")
                lbl_desc.config(bg="#1E3A8A", fg="#FFFFFF", font=("Helvetica", 9, "bold"))
            else:
                frame.config(bg="#0F172A", bd=1, relief="ridge")
                lbl_code.config(bg="#334155", fg="#F8FAFC")
                lbl_desc.config(bg="#0F172A", fg="#94A3B8", font=("Helvetica", 9))
        self.root.after(0, _apply)

    def update_pdu_display(self, text):
        self.root.after(0, lambda: self.lbl_pdu_inspect.config(text=text))

    def reset_simulation(self):
        if self.is_simulating:
            return
        self.txt_log.delete("1.0", tk.END)
        self.lbl_pdu_inspect.config(text="Esperando transmisión...")
        self.lbl_channel_status.config(text="IDLE", fg="#94A3B8")
        self.lbl_channel_arrow.config(fg="#64748B")
        self.log("Simulador reiniciado. Listo para nueva evaluación.", "INFO")


# ==============================================================================
# PUNTO DE ENTRADA PRINCIPAL DE LA APLICACIÓN
# ==============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = OSINetworkSimulatorGUI(root)
    root.mainloop()