#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Monitor — modo gNMI-compat + optimización cambio-only
- Usa solo HC counters (64-bit)
- last-update como int64 (compatible con gNMI)
- Solo emite métricas que cambiaron (como hace gNMI en modo on-change+sample)
- Estructura JSON idéntica a la salida de gnmic
"""

import time
import json
import sys
from datetime import datetime, timezone
from easysnmp import Session, EasySNMPError

# =========================
# Configuración fija
# =========================
TARGET = '172.100.100.7'
COMMUNITY = 'public'
POLL_INTERVAL = 5  # segundos
OUTPUT_FILE = '/data/if-stats-snmp.json'

INTERFACE_INDEX = 2  # ifIndex de Ethernet2

# Mapeo OID → nombre gNMI (YANG)
OID_MAP = {
    # HC counters (64-bit)
    'in-octets':           '.1.3.6.1.2.1.31.1.1.1.6',   # ifHCInOctets
    'in-unicast-pkts':     '.1.3.6.1.2.1.31.1.1.1.7',   # ifHCInUcastPkts
    'in-multicast-pkts':   '.1.3.6.1.2.1.31.1.1.1.8',   # ifHCInMulticastPkts
    'in-broadcast-pkts':   '.1.3.6.1.2.1.31.1.1.1.9',   # ifHCInBroadcastPkts
    'out-octets':          '.1.3.6.1.2.1.31.1.1.1.10',  # ifHCOutOctets
    'out-unicast-pkts':    '.1.3.6.1.2.1.31.1.1.1.11',  # ifHCOutUcastPkts
    'out-multicast-pkts':  '.1.3.6.1.2.1.31.1.1.1.12',  # ifHCOutMulticastPkts
    'out-broadcast-pkts':  '.1.3.6.1.2.1.31.1.1.1.13',  # ifHCOutBroadcastPkts

    # Errors/Discards (32-bit estándar)
    'in-discards':         '.1.3.6.1.2.1.2.2.1.13',     # ifInDiscards
    'in-errors':           '.1.3.6.1.2.1.2.2.1.14',     # ifInErrors
    'out-discards':        '.1.3.6.1.2.1.2.2.1.19',     # ifOutDiscards
    'out-errors':          '.1.3.6.1.2.1.2.2.1.20',     # ifOutErrors

    # Otros
    'carrier-transitions': '.1.3.6.1.2.1.2.2.1.9',      # ifAdminStatus changes
}


class SNMPMonitorGNMICompat:
    def __init__(self, target, community, if_index):
        self.target = target
        self.community = community
        self.if_index = if_index
        self.session = None
        self.prev_counters = {}
        self._init_session()

    def _init_session(self):
        try:
            self.session = Session(
                hostname=self.target,
                community=self.community,
                version=2,
                timeout=3,
                retries=2
            )
        except EasySNMPError as e:
            print(f"❌ Error al inicializar SNMP: {e}", file=sys.stderr)
            sys.exit(1)

    def get_counter(self, oid_name):
        oid_base = OID_MAP[oid_name]
        oid = f"{oid_base}.{self.if_index}"
        try:
            res = self.session.get(oid)
            if res and res.value and res.value not in ('NOSUCHINSTANCE', 'NOSUCHOBJECT', ''):
                return str(res.value)
        except Exception:
            pass
        return "0"

    def collect_counters(self):
        """Obtiene contadores y filtra solo los que cambiaron (optimización gNMI-style)"""
        # --- Obtener valores crudos ---
        raw = {k: self.get_counter(k) for k in OID_MAP.keys()}

        # --- Calcular totales (como hace YANG) ---
        in_pkts = sum(int(raw.get(f, 0)) for f in ['in-unicast-pkts', 'in-multicast-pkts', 'in-broadcast-pkts'])
        out_pkts = sum(int(raw.get(f, 0)) for f in ['out-unicast-pkts', 'out-multicast-pkts', 'out-broadcast-pkts'])
        raw['in-pkts'] = str(in_pkts)
        raw['out-pkts'] = str(out_pkts)

        # --- Filtrar solo cambios ---
        changed = {k: v for k, v in raw.items() if v != self.prev_counters.get(k)}
        self.prev_counters = raw

        # Si nada cambió, devolver todo (modo polling fallback)
        return changed if changed else raw

    def emit_update(self, path, values, ts_ns, prefix=None):
        """Genera un objeto de actualización compatible con gNMI JSON"""
        base = {
            "source": "router-edge",
            "subscription-name": "snmp_interface_stats",
            "timestamp": ts_ns,
            "time": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()
        }
        if prefix:
            base["prefix"] = prefix
            # Si `values` es dict, desglosar en múltiples updates
            if isinstance(values, dict):
                base["updates"] = [{"Path": k, "values": {k: v}} for k, v in values.items()]
            else:
                # No debería ocurrir, pero fallback
                base["updates"] = [{"Path": path, "values": {path: values}}]
        else:
            # `values` es un solo valor (string o int)
            base["updates"] = [{"Path": path, "values": {path: values}}]
        return base

    def run(self):
        print("▶ Iniciando monitoreo SNMP (modo gNMI-compat + cambio-only)...")
        print("  Guardando en:", OUTPUT_FILE)
        print("  Ctrl+C para detener\n")

        with open(OUTPUT_FILE, 'w') as f:
            iteration = 0
            while True:
                try:
                    ts = time.time()
                    ts_ns = int(ts * 1e9)

                    counters = self.collect_counters()

                    # ---------- 1. last-update (siempre se emite) ----------
                    last_update_path = "interfaces/interface[name=Ethernet2]/state/counters/last-update"
                    # ✅ CORREGIDO: ahora es int64, no string
                    json.dump(self.emit_update(last_update_path, ts_ns, ts_ns), f)
                    f.write("\n")

                    # ---------- 2. carrier-transitions (si cambió o primera vez) ----------
                    if 'carrier-transitions' in counters:
                        ct_path = "interfaces/interface[name=Ethernet2]/state/counters/carrier-transitions"
                        json.dump(self.emit_update(ct_path, counters['carrier-transitions'], ts_ns), f)
                        f.write("\n")

                    # ---------- 3. Métricas grupales con prefix ----------
                    # Separar en bloques coherentes (como en tu gNMI output)

                    # Bloque: errores/discards (solo si hay cambios)
                    error_block = {
                        k: counters[k] for k in ['in-discards', 'in-errors', 'out-discards', 'out-errors']
                        if k in counters
                    }
                    if error_block:
                        json.dump(self.emit_update("", error_block, ts_ns,
                                    prefix="interfaces/interface[name=Ethernet2]/state/counters"), f)
                        f.write("\n")

                    # Bloque: broadcast (opcional, para IPv4 legacy)
                    bc_block = {
                        k: counters[k] for k in ['in-broadcast-pkts', 'out-broadcast-pkts']
                        if k in counters
                    }
                    if bc_block:
                        json.dump(self.emit_update("", bc_block, ts_ns,
                                    prefix="interfaces/interface[name=Ethernet2]/state/counters"), f)
                        f.write("\n")

                    # Bloque: in-* (octets, pkts, unicast, multicast) — solo si cambiaron
                    in_block = {
                        k: counters[k] for k in ['in-octets', 'in-pkts', 'in-unicast-pkts', 'in-multicast-pkts']
                        if k in counters
                    }
                    if in_block:
                        # Si in-multicast-pkts está presente y es el único → emitir por separado (como en gNMI)
                        if len(in_block) == 1 and 'in-multicast-pkts' in in_block:
                            mc_path = "interfaces/interface[name=Ethernet2]/state/counters/in-multicast-pkts"
                            json.dump(self.emit_update(mc_path, in_block['in-multicast-pkts'], ts_ns), f)
                            f.write("\n")
                        else:
                            json.dump(self.emit_update("", in_block, ts_ns,
                                        prefix="interfaces/interface[name=Ethernet2]/state/counters"), f)
                            f.write("\n")

                    # Bloque: out-* (análogo)
                    out_block = {
                        k: counters[k] for k in ['out-octets', 'out-pkts', 'out-unicast-pkts', 'out-multicast-pkts']
                        if k in counters
                    }
                    if out_block:
                        if len(out_block) == 1 and 'out-multicast-pkts' in out_block:
                            mc_path = "interfaces/interface[name=Ethernet2]/state/counters/out-multicast-pkts"
                            json.dump(self.emit_update(mc_path, out_block['out-multicast-pkts'], ts_ns), f)
                            f.write("\n")
                        else:
                            json.dump(self.emit_update("", out_block, ts_ns,
                                        prefix="interfaces/interface[name=Ethernet2]/state/counters"), f)
                            f.write("\n")

                    f.flush()

                    # Log resumido
                    in_oct = counters.get('in-octets', '—')
                    out_oct = counters.get('out-octets', '—')
                    in_mc = counters.get('in-multicast-pkts', '—')
                    out_mc = counters.get('out-multicast-pkts', '—')
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"↻ Iter {iteration+1} (+{len(counters)} cambios) | "
                          f"in={in_oct} out={out_oct} | mc-in={in_mc} mc-out={out_mc}")

                    iteration += 1
                    time.sleep(POLL_INTERVAL)

                except KeyboardInterrupt:
                    print("\n⏹️ Monitoreo detenido por usuario.")
                    break
                except Exception as e:
                    print(f"⚠ Error en iteración: {e}", file=sys.stderr)
                    time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    monitor = SNMPMonitorGNMICompat(TARGET, COMMUNITY, INTERFACE_INDEX)
    monitor.run()
