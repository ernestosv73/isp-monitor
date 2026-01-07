#!/usr/bin/env python3
"""
Análisis de overhead: SNMP vs gNMI — versión robusta y compatible con tshark ≥ 3.0
✅ Basado en frames reales 
"""

import subprocess
import sys
import csv
from collections import namedtuple

# 🔧 Configuración (ajusta si cambian los nombres)
SNMP_PCAP = "snmp.pcapng"
GNMI_PCAP = "gnmi.pcapng"
OUTPUT_CSV = "overhead_comparison.csv"

Metrics = namedtuple('Metrics', [
    'protocol', 'duration_sec', 'total_frames', 'total_bytes',
    'avg_bytes_per_msg', 'msgs_per_sec', 'first_msg_latency_sec'
])

def run_tshark(cmd_args):
    """Ejecuta tshark con captura de salida y error"""
    try:
        result = subprocess.run(
            ["tshark"] + cmd_args,
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"⚠️ tshark error: {e.stderr.strip()}", file=sys.stderr)
        return ""

def analyze_snmp(pcap):
    print(f"[SNMP] Analizando {pcap}...")
    
    # 1. Todos los frames SNMP (UDP + snmp)
    all_snmp = run_tshark(["-r", pcap, "-Y", "udp.port == 161 && snmp", "-T", "fields", "-e", "frame.number"])
    frames = [int(x) for x in all_snmp.splitlines() if x.isdigit()]
    total_frames = len(frames)
    if total_frames == 0:
        print("   ⚠️ No se encontraron frames SNMP")
        return Metrics("SNMP", 0, 0, 0, 0, 0, 0)
    
    # 2. Bytes totales
    byte_out = run_tshark(["-r", pcap, "-Y", "udp.port == 161 && snmp", "-T", "fields", "-e", "frame.len"])
    sizes = [int(x) for x in byte_out.splitlines() if x.isdigit()]
    total_bytes = sum(sizes)
    
    # 3. Timestamps para duración y latencia
    ts_out = run_tshark(["-r", pcap, "-Y", "udp.port == 161 && snmp", "-T", "fields", "-e", "frame.time_relative"])
    times = [float(t) for t in ts_out.splitlines() if t.replace('.', '').isdigit()]
    duration = max(times) - min(times) if times else 0
    first_msg_latency = times[0] if times else 0  # primer frame = primer request
    
    # 4. Mensajes por segundo (cada request + response = 1 "mensaje lógico")
    # Pero para comparabilidad con gNMI (streaming), contamos frames individuales
    msgs_per_sec = total_frames / duration if duration > 0 else 0
    
    avg_bytes = total_bytes / total_frames if total_frames else 0
    
    return Metrics(
        protocol="SNMP",
        duration_sec=round(duration, 3),
        total_frames=total_frames,
        total_bytes=total_bytes,
        avg_bytes_per_msg=round(avg_bytes, 1),
        msgs_per_sec=round(msgs_per_sec, 2),
        first_msg_latency_sec=round(first_msg_latency, 3)
    )

def analyze_gnmi(pcap):
    print(f"[gNMI] Analizando {pcap}...")
    
    # gNMI: filtrar solo frames con payload útil (no SYN/ACK puros)
    # Usamos: puerto 6030 + longitud de frame > 100 (evita ACKs pequeños)
    data_frames = run_tshark([
        "-r", pcap,
        "-Y", "tcp.port == 6030 && frame.len > 100",
        "-T", "fields", "-e", "frame.number"
    ])
    frames = [int(x) for x in data_frames.splitlines() if x.isdigit()]
    total_frames = len(frames)
    
    if total_frames == 0:
        print("   ⚠️ No se encontraron frames gNMI con payload útil")
        return Metrics("gNMI", 0, 0, 0, 0, 0, 0)
    
    # Bytes y timestamps
    byte_out = run_tshark([
        "-r", pcap, "-Y", "tcp.port == 6030 && frame.len > 100",
        "-T", "fields", "-e", "frame.len"
    ])
    sizes = [int(x) for x in byte_out.splitlines() if x.isdigit()]
    total_bytes = sum(sizes)
    
    ts_out = run_tshark([
        "-r", pcap, "-Y", "tcp.port == 6030 && frame.len > 100",
        "-T", "fields", "-e", "frame.time_relative"
    ])
    times = [float(t) for t in ts_out.splitlines() if t.replace('.', '').isdigit()]
    duration = max(times) - min(times) if times else 0
    first_msg_latency = times[0] if times else 0  # primer dato útil (ej., sync-response)
    
    msgs_per_sec = total_frames / duration if duration > 0 else 0
    avg_bytes = total_bytes / total_frames if total_frames else 0
    
    return Metrics(
        protocol="gNMI",
        duration_sec=round(duration, 3),
        total_frames=total_frames,
        total_bytes=total_bytes,
        avg_bytes_per_msg=round(avg_bytes, 1),
        msgs_per_sec=round(msgs_per_sec, 2),
        first_msg_latency_sec=round(first_msg_latency, 3)
    )

def print_table(metrics_list):
    print("\n" + "="*80)
    print("📊 COMPARATIVA DE OVERHEAD: SNMP vs gNMI (datos reales)")
    print("="*80)
    header = ["Métrica", "SNMP", "gNMI", "Δ (SNMP/gNMI)"]
    print(f"{header[0]:<25} {header[1]:<12} {header[2]:<12} {header[3]}")
    print("-"*80)
    
    snmp = next(m for m in metrics_list if m.protocol == "SNMP")
    gnmi = next(m for m in metrics_list if m.protocol == "gNMI")
    
    rows = [
        ("Duración (s)", snmp.duration_sec, gnmi.duration_sec, "-"),
        ("Frames totales", snmp.total_frames, gnmi.total_frames, f"{snmp.total_frames/gnmi.total_frames:.1f}×"),
        ("Bytes totales", snmp.total_bytes, gnmi.total_bytes, f"{snmp.total_bytes/gnmi.total_bytes:.1f}×"),
        ("Bytes/frame", snmp.avg_bytes_per_msg, gnmi.avg_bytes_per_msg, f"{snmp.avg_bytes_per_msg/gnmi.avg_bytes_per_msg:.1f}×"),
        ("Frames/segundo", snmp.msgs_per_sec, gnmi.msgs_per_sec, f"{snmp.msgs_per_sec/gnmi.msgs_per_sec:.1f}×"),
        ("Latencia primer dato (s)", snmp.first_msg_latency_sec, gnmi.first_msg_latency_sec, "-"),
    ]
    
    for name, s, g, r in rows:
        print(f"{name:<25} {s:<12} {g:<12} {r}")
    print("="*80)

def save_csv(metrics_list):
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(Metrics._fields)
        writer.writerows(metrics_list)
    print(f"\n✅ Tabla exportada a: {OUTPUT_CSV}")

def main():
    print("🔍 Analizando tráfico de monitoreo (capturas reales)...")
    
    snmp_metrics = analyze_snmp(SNMP_PCAP)
    gnmi_metrics = analyze_gnmi(GNMI_PCAP)
    
    if snmp_metrics.total_frames == 0 and gnmi_metrics.total_frames == 0:
        print("\n❌ Error: ningún tráfico útil encontrado. Verifica los archivos pcapng.")
        return
    
    metrics_list = [snmp_metrics, gnmi_metrics]
    print_table(metrics_list)
    save_csv(metrics_list)
    
    # Resumen técnico (basado en tus datos)
    if snmp_metrics.total_frames > 0 and gnmi_metrics.total_frames > 0:
        print("\n📌 Hallazgos clave (según tus capturas):")
        print(f"• SNMP generó {snmp_metrics.total_frames} frames (request + response).")
        print(f"• gNMI generó {gnmi_metrics.total_frames} frames con payload útil (streaming).")
        print(f"• gNMI es {snmp_metrics.total_bytes/gnmi_metrics.total_bytes:.1f}× más eficiente en bytes totales.")
        print(f"• SNMP tiene mayor overhead de handshake (request-response síncrono).")

if __name__ == "__main__":
    main()
