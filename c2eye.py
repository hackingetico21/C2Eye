#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
C2Eye - Monitor de Conexiones Maliciosas
Versión 1.0 - 2026
Autor: La IA y Kcius...en realidad fue mas la IA yo solo revise que todo estuviera bien.
Descripción: Herramienta portable para monitorear conexiones de red en tiempo real,
             geolocalizar IPs y matar procesos maliciosos.
"""

import sys
import os
import subprocess
import threading
import time
import json
import urllib.request
from datetime import datetime
from collections import deque

# Intentar importar las librerías necesarias
try:
    import psutil
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QColor, QBrush, QIcon
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                                 QHBoxLayout, QTableWidget, QTableWidgetItem,
                                 QPushButton, QLabel, QTextEdit, QHeaderView,
                                 QMessageBox, QProgressBar, QMenu, QAction,
                                 QSystemTrayIcon, QFrame, QSplitter)
except ImportError:
    print("[!] Error: Faltan librerías. Ejecuta: pip install psutil PyQt5")
    sys.exit(1)

# ============================================================
# CONFIGURACIÓN
# ============================================================
GEOIP_API = "http://ip-api.com/json/{}"
REFRESH_INTERVAL = 1000  # milisegundos
MAX_LOG_LINES = 1000
WINDOW_TITLE = "C2Eye - Monitor de Conexiones"
WINDOW_WIDTH = 1100
WINDOW_HEIGHT = 700

# Colores (modo oscuro)
COLORS = {
    'bg_dark': '#1a1a2e',
    'bg_medium': '#16213e',
    'bg_light': '#0f3460',
    'text_primary': '#e0e0e0',
    'text_secondary': '#8899bb',
    'accent': '#00d4ff',
    'danger': '#ff6b6b',
    'success': '#51cf66',
    'warning': '#fcc419',
    'border': '#2a2a4a'
}


# ============================================================
# UTILIDADES
# ============================================================
def get_process_name(pid):
    """Obtiene el nombre del proceso dado un PID."""
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "N/A"


def get_ip_location(ip):
    """Consulta la ubicación de una IP usando ip-api.com."""
    if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
        return "Local / Privada"
    
    try:
        url = GEOIP_API.format(ip)
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                return f"{data.get('country', 'N/A')} - {data.get('city', 'N/A')}"
            return "No disponible"
    except Exception:
        return "Error al consultar"


def kill_process(pid):
    """Fuerza la terminación de un proceso dado su PID."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        time.sleep(0.5)
        if proc.is_running():
            proc.kill()
        return True, f"Proceso {pid} finalizado"
    except psutil.NoSuchProcess:
        return False, "El proceso ya no existe"
    except psutil.AccessDenied:
        return False, "Acceso denegado (necesitas permisos de administrador)"
    except Exception as e:
        return False, f"Error: {str(e)}"


# ============================================================
# HILO DE MONITOREO
# ============================================================
class NetworkMonitor(QThread):
    """Hilo que monitorea las conexiones de red en segundo plano."""
    
    data_updated = pyqtSignal(list)
    log_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.mutex = threading.Lock()
        self.connections = []
        self.history = deque(maxlen=100)
    
    def run(self):
        while self.running:
            try:
                connections = self.get_connections()
                with self.mutex:
                    self.connections = connections
                self.data_updated.emit(connections)
            except Exception as e:
                self.log_message.emit(f"[!] Error en monitor: {e}")
            time.sleep(REFRESH_INTERVAL / 1000)
    
    def get_connections(self):
        """Obtiene todas las conexiones de red activas."""
        connections = []
        
        # Obtener conexiones TCP
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == 'ESTABLISHED' or conn.status == 'SYN_SENT':
                if conn.raddr:
                    ip, port = conn.raddr
                    if ip == '0.0.0.0' or ip == '127.0.0.1':
                        continue
                    connections.append({
                        'pid': conn.pid,
                        'process': get_process_name(conn.pid),
                        'local_ip': conn.laddr.ip if conn.laddr else 'N/A',
                        'local_port': conn.laddr.port if conn.laddr else 'N/A',
                        'remote_ip': ip,
                        'remote_port': port,
                        'status': conn.status,
                        'type': 'TCP',
                        'timestamp': datetime.now().strftime('%H:%M:%S')
                    })
        
        # Obtener conexiones UDP
        for conn in psutil.net_connections(kind='udp'):
            if conn.raddr:
                ip, port = conn.raddr
                if ip == '0.0.0.0' or ip == '127.0.0.1':
                    continue
                connections.append({
                    'pid': conn.pid,
                    'process': get_process_name(conn.pid),
                    'local_ip': conn.laddr.ip if conn.laddr else 'N/A',
                    'local_port': conn.laddr.port if conn.laddr else 'N/A',
                    'remote_ip': ip,
                    'remote_port': port,
                    'status': 'UDP',
                    'type': 'UDP',
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })
        
        # Ordenar por timestamp (más recientes primero)
        connections.sort(key=lambda x: x['timestamp'], reverse=True)
        return connections
    
    def stop(self):
        self.running = False


# ============================================================
# VENTANA PRINCIPAL
# ============================================================
class C2EyeWindow(QMainWindow):
    """Ventana principal de la aplicación."""
    
    def __init__(self):
        super().__init__()
        self.monitor = NetworkMonitor()
        self.monitor.data_updated.connect(self.update_table)
        self.monitor.log_message.connect(self.add_log)
        
        self.connection_cache = {}
        self.geo_cache = {}
        
        self.init_ui()
        self.init_tray()
        self.start_monitoring()
    
    def init_ui(self):
        """Configura la interfaz de usuario."""
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setStyleSheet(self.get_stylesheet())
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # --- Barra superior ---
        top_bar = QHBoxLayout()
        
        # Título y estado
        title_label = QLabel("🛡️ C2Eye")
        title_label.setStyleSheet("font-size: 22px; font-weight: bold; color: #00d4ff;")
        top_bar.addWidget(title_label)
        
        top_bar.addStretch()
        
        # Contador de conexiones
        self.conn_counter = QLabel("Conexiones: 0")
        self.conn_counter.setStyleSheet("color: #8899bb; font-size: 14px;")
        top_bar.addWidget(self.conn_counter)
        
        # Botón limpiar
        clear_btn = QPushButton("🧹 Limpiar")
        clear_btn.clicked.connect(self.clear_table)
        clear_btn.setFixedWidth(100)
        top_bar.addWidget(clear_btn)
        
        # Botón actualizar
        refresh_btn = QPushButton("🔄 Actualizar")
        refresh_btn.clicked.connect(self.force_refresh)
        refresh_btn.setFixedWidth(100)
        top_bar.addWidget(refresh_btn)
        
        main_layout.addLayout(top_bar)
        
        # --- Tabla de conexiones ---
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels([
            "⏱️ Tiempo", "🔢 PID", "📦 Proceso", "🌐 IP Origen",
            "🔌 Puerto", "🎯 IP Destino", "📡 Puerto", "📊 Estado", "🌍 Ubicación"
        ])
        
        # Configurar columnas
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 60)
        self.table.setColumnWidth(2, 180)
        self.table.setColumnWidth(3, 130)
        self.table.setColumnWidth(4, 70)
        self.table.setColumnWidth(5, 130)
        self.table.setColumnWidth(6, 70)
        self.table.setColumnWidth(7, 90)
        self.table.setColumnWidth(8, 180)
        
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        
        # Conectar evento de clic para geolocalización
        self.table.itemClicked.connect(self.on_table_click)
        
        main_layout.addWidget(self.table)
        
        # --- Botones de acción ---
        action_layout = QHBoxLayout()
        
        self.kill_btn = QPushButton("💀 Matar proceso seleccionado")
        self.kill_btn.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold;")
        self.kill_btn.clicked.connect(self.kill_selected_process)
        self.kill_btn.setEnabled(False)
        action_layout.addWidget(self.kill_btn)
        
        self.geo_btn = QPushButton("🌍 Geolocalizar selección")
        self.geo_btn.clicked.connect(self.geolocate_selected)
        self.geo_btn.setEnabled(False)
        action_layout.addWidget(self.geo_btn)
        
        self.kill_all_btn = QPushButton("🔪 Matar todos los procesos sospechosos")
        self.kill_all_btn.setStyleSheet("background-color: #e74c3c; color: white;")
        self.kill_all_btn.clicked.connect(self.kill_all_suspicious)
        action_layout.addWidget(self.kill_all_btn)
        
        action_layout.addStretch()
        
        main_layout.addLayout(action_layout)
        
        # --- Log de eventos ---
        log_label = QLabel("📋 Log de eventos")
        log_label.setStyleSheet("color: #8899bb; font-weight: bold;")
        main_layout.addWidget(log_label)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(120)
        self.log_text.setStyleSheet("""
            background-color: #0d0d1a;
            color: #aabbcc;
            border: 1px solid #2a2a4a;
            border-radius: 4px;
            font-family: Consolas, monospace;
            font-size: 12px;
        """)
        main_layout.addWidget(self.log_text)
        
        # Barra de estado
        self.status_bar = self.statusBar()
        self.status_bar.setStyleSheet("color: #8899bb;")
        self.status_bar.showMessage("🟢 C2Eye iniciado - Monitoreando conexiones...")
    
    def get_stylesheet(self):
        """Retorna los estilos CSS para la ventana."""
        return f"""
            QMainWindow {{
                background-color: {COLORS['bg_dark']};
            }}
            QWidget {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            }}
            QTableWidget {{
                background-color: {COLORS['bg_medium']};
                alternate-background-color: #1e2a3a;
                color: {COLORS['text_primary']};
                gridline-color: {COLORS['border']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                selection-background-color: {COLORS['accent']};
                selection-color: #1a1a2e;
            }}
            QTableWidget::item {{
                padding: 6px 8px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_secondary']};
                padding: 8px;
                border: none;
                font-weight: bold;
                font-size: 11px;
            }}
            QPushButton {{
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
                color: {COLORS['bg_dark']};
            }}
            QPushButton:disabled {{
                opacity: 0.5;
            }}
            QLabel {{
                color: {COLORS['text_primary']};
            }}
            QTextEdit {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
            QProgressBar {{
                background-color: {COLORS['bg_medium']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['accent']};
                border-radius: 4px;
            }}
        """
    
    def init_tray(self):
        """Inicializa el icono de la bandeja del sistema."""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon.fromTheme("network"))
        self.tray_icon.setToolTip("C2Eye - Monitor de Conexiones")
        self.tray_icon.activated.connect(self.tray_activated)
        self.tray_icon.show()
    
    def tray_activated(self, reason):
        """Maneja el clic en el icono de la bandeja."""
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isVisible():
                self.hide()
            else:
                self.show()
                self.raise_()
                self.activateWindow()
    
    def start_monitoring(self):
        """Inicia el hilo de monitoreo."""
        self.monitor.start()
        self.add_log("[+] Monitor iniciado")
        self.status_bar.showMessage("🟢 Monitoreando conexiones...")
    
    def update_table(self, connections):
        """Actualiza la tabla con las conexiones detectadas."""
        # Preservar la selección actual
        current_row = self.table.currentRow()
        current_ip = None
        if current_row >= 0:
            current_ip = self.table.item(current_row, 5).text() 
        
        self.table.setRowCount(0)
        
        for conn in connections:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # Timestamp
            self.table.setItem(row, 0, QTableWidgetItem(conn.get('timestamp', 'N/A')))
            
            # PID
            pid_item = QTableWidgetItem(str(conn.get('pid', 'N/A')))
            self.table.setItem(row, 1, pid_item)
            
            # Proceso
            self.table.setItem(row, 2, QTableWidgetItem(conn.get('process', 'N/A')))
            
            # IP Origen
            self.table.setItem(row, 3, QTableWidgetItem(conn.get('local_ip', 'N/A')))
            
            # Puerto Origen
            self.table.setItem(row, 4, QTableWidgetItem(str(conn.get('local_port', 'N/A'))))
            
            # IP Destino
            ip_dest = conn.get('remote_ip', 'N/A')
            ip_item = QTableWidgetItem(ip_dest)
            # Resaltar IPs públicas
            if ip_dest and not ip_dest.startswith('192.168.') and not ip_dest.startswith('10.'):
                ip_item.setForeground(QBrush(QColor(COLORS['warning'])))
            self.table.setItem(row, 5, ip_item)
            
            # Puerto Destino
            self.table.setItem(row, 6, QTableWidgetItem(str(conn.get('remote_port', 'N/A'))))
            
            # Estado
            status = conn.get('status', 'N/A')
            status_item = QTableWidgetItem(status)
            if status == 'ESTABLISHED':
                status_item.setForeground(QBrush(QColor(COLORS['success'])))
            elif status == 'SYN_SENT':
                status_item.setForeground(QBrush(QColor(COLORS['warning'])))
            self.table.setItem(row, 7, status_item)
            
            # Ubicación (se consulta bajo demanda)
            location_item = QTableWidgetItem("")
            if ip_dest and ip_dest not in self.geo_cache:
                if ip_dest not in self.geo_cache:
                    self.geo_cache[ip_dest] = "Consultando..."
                location_item.setText(self.geo_cache[ip_dest])
            else:
                location_item.setText(self.geo_cache.get(ip_dest, ""))
            self.table.setItem(row, 8, location_item)
        
        # Actualizar contador
        self.conn_counter.setText(f"Conexiones: {self.table.rowCount()}")
        
        # Restaurar selección si es posible
        if current_ip:
            for row in range(self.table.rowCount()):
                if self.table.item(row, 5).text() == current_ip:
                    self.table.selectRow(row)
                    break
    
    def on_table_click(self, item):
        """Maneja el clic en la tabla para geolocalización automática."""
        row = item.row()
        ip_item = self.table.item(row, 5)
        if ip_item:
            ip = ip_item.text()
            if ip and ip not in self.geo_cache:
                self.geo_cache[ip] = "Consultando..."
                # Consultar en un hilo separado
                threading.Thread(target=self.fetch_location, args=(row, ip), daemon=True).start()
        
        # Habilitar botones
        self.kill_btn.setEnabled(True)
        self.geo_btn.setEnabled(True)
    
    def fetch_location(self, row, ip):
        """Consulta la ubicación de una IP en segundo plano."""
        location = get_ip_location(ip)
        self.geo_cache[ip] = location
        # Actualizar la tabla en el hilo principal
        QtCore.QMetaObject.invokeMethod(self, "update_location", QtCore.Qt.QueuedConnection, 
                                        QtCore.Q_ARG(int, row), QtCore.Q_ARG(str, location))
    
    def update_location(self, row, location):
        """Actualiza la ubicación en la tabla (ejecutado en el hilo principal)."""
        if row < self.table.rowCount():
            self.table.setItem(row, 8, QTableWidgetItem(location))
            self.add_log(f"[+] Ubicación consultada: {location}")
    
    def geolocate_selected(self):
        """Geolocaliza la IP seleccionada manualmente."""
        selected = self.table.selectedItems()
        if selected:
            row = selected[0].row()
            ip_item = self.table.item(row, 5)
            if ip_item:
                ip = ip_item.text()
                location = get_ip_location(ip)
                self.geo_cache[ip] = location
                self.table.setItem(row, 8, QTableWidgetItem(location))
                self.add_log(f"[+] Geolocalización manual: {ip} → {location}")
                QMessageBox.information(self, "Geolocalización", 
                                        f"IP: {ip}\nUbicación: {location}")
    
    def kill_selected_process(self):
        """Mata el proceso seleccionado en la tabla."""
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Advertencia", "Selecciona una conexión primero.")
            return
        
        row = selected[0].row()
        pid_item = self.table.item(row, 1)
        proc_item = self.table.item(row, 2)
        ip_item = self.table.item(row, 5)
        
        if not pid_item or pid_item.text() == 'N/A':
            QMessageBox.warning(self, "Advertencia", "No se puede obtener el PID de esta conexión.")
            return
        
        pid = int(pid_item.text())
        proc_name = proc_item.text() if proc_item else "Desconocido"
        ip = ip_item.text() if ip_item else "Desconocida"
        
        # Confirmar
        reply = QMessageBox.question(
            self, "Confirmar",
            f"¿Estás seguro de que quieres matar el proceso?\n\n"
            f"PID: {pid}\nProceso: {proc_name}\nIP Destino: {ip}\n\n"
            f"Esta acción es irreversible.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message = kill_process(pid)
            if success:
                self.add_log(f"[+] Proceso {pid} ({proc_name}) finalizado. IP: {ip}")
                self.status_bar.showMessage(f"✅ Proceso {pid} finalizado")
                QMessageBox.information(self, "Éxito", f"Proceso {pid} finalizado correctamente.")
            else:
                self.add_log(f"[!] Error al finalizar proceso {pid}: {message}")
                self.status_bar.showMessage(f"❌ Error: {message}")
                QMessageBox.critical(self, "Error", message)
    
    def kill_all_suspicious(self):
        """Mata todos los procesos con conexiones a IPs públicas."""
        suspicious = []
        for row in range(self.table.rowCount()):
            pid_item = self.table.item(row, 1)
            ip_item = self.table.item(row, 5)
            if pid_item and ip_item:
                ip = ip_item.text()
                if ip and not ip.startswith('192.168.') and not ip.startswith('10.'):
                    suspicious.append((int(pid_item.text()), ip))
        
        if not suspicious:
            QMessageBox.information(self, "Info", "No hay procesos sospechosos detectados.")
            return
        
        reply = QMessageBox.question(
            self, "Confirmar",
            f"Se encontraron {len(suspicious)} procesos con conexiones a IPs públicas.\n\n"
            f"¿Quieres finalizar todos estos procesos?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            killed = 0
            for pid, ip in suspicious:
                success, _ = kill_process(pid)
                if success:
                    killed += 1
                    self.add_log(f"[+] Proceso {pid} finalizado (IP: {ip})")
            
            self.add_log(f"[+] Procesos finalizados: {killed}/{len(suspicious)}")
            self.status_bar.showMessage(f"✅ {killed} procesos finalizados")
            QMessageBox.information(self, "Éxito", f"{killed} procesos finalizados correctamente.")
    
    def clear_table(self):
        """Limpia la tabla de conexiones."""
        self.table.setRowCount(0)
        self.add_log("[+] Tabla limpiada")
        self.status_bar.showMessage("🧹 Tabla limpiada")
    
    def force_refresh(self):
        """Fuerza una actualización manual."""
        self.status_bar.showMessage("🔄 Actualizando...")
        self.add_log("[+] Actualización manual solicitada")
        # Obtener conexiones directamente
        connections = self.monitor.get_connections()
        self.update_table(connections)
        self.status_bar.showMessage("✅ Actualización completa")
    
    def add_log(self, message):
        """Añade un mensaje al log."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
        # Mantener el scroll al final
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        # Limitar líneas
        if self.log_text.document().blockCount() > MAX_LOG_LINES:
            cursor = self.log_text.textCursor()
            cursor.movePosition(QtGui.QTextCursor.Start)
            cursor.movePosition(QtGui.QTextCursor.Down, QtGui.QTextCursor.KeepAnchor, 
                              self.log_text.document().blockCount() - MAX_LOG_LINES)
            cursor.removeSelectedText()
    
    def closeEvent(self, event):
        """Maneja el cierre de la aplicación."""
        self.monitor.stop()
        self.monitor.wait()
        self.tray_icon.hide()
        event.accept()


# ============================================================
# MAIN
# ============================================================
def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName("C2Eye")
    app.setApplicationDisplayName("C2Eye - Monitor de Conexiones")
    
    # Configurar icono (si existe)
    icon_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    window = C2EyeWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
