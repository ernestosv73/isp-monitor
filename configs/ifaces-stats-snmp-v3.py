#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Monitor — modo *on-change puro* (hoja por hoja)
- Solo emite un campo cuando su valor cambia (como hace Arista gNMI en práctica)
- Sin bloques: cada leaf es un update individual
- Omitir valores 0 en out-discards/in-discards/etc., salvo en octets/pkts
- Compatible con Ethernet1 y Ethernet2
- Estructura JSON idéntica a gnmic
"""

import time
import json
import sys
from datetime import datetime, timezone
from easysnmp import Session, EasySNMPError

# =========================
# Configuración
# =========================
TARGET = '172.100.100.7'
COMMUNITY = 'public'
POLL_INTERVAL = 5  # segundos
OUTPUT_FILE = '/data/if-stats-snmp.json'

# Mapeo OID → nombre YANG
OID_MAP = {
    'in-octets':           '.1.3.6.1.2.1.31.1.1.1.6',
    'in-unicast-pkts':     '.1.3.6.1.2.1.31.1.1.1.7',
    'in-multicast-pkts':   '.1.3.6.1.2.1.31.1.1.1.8',
    'in-broadcast-pkts':   '.1.3.6.1.2.1.31.1.1.1.9',
    'out-octets':          '.1.3.6.1.2.1.31.1.1.1.10',
    'out-unicast-pkts':    '.1.3.6.1.2.1.31.1.1.1.11',
    'out-multicast-pkts':  '.1.3.6.1.2.1.31.1.1.1.12',
    'out-broadcast-pkts':  '.1.3.6.1.2.1.31.1.1.1.13',
    'in-discards':         '.1.3.6.1.2.1.2.2.1.13',
    'in-errors':           '.1.3.6.1.2.1.2.2.1.14',
    'out-discards':        '.1.3.6.1.2.1.2.2.1.19',
    'out-errors':          '.1.3.6.1.2.1.2.2.1.20',
    'carrier-transitions': '.1.3.6.1.2.1.2.2.1.9',
}


class SNMPLeafMonitor:
    def __init__(self, session, if_index, if_name):
        self.session = session
        self.if_index = if_index
        self.if_name = if_name
        self.prev_values = {key: None for key in OID_MAP.keys()}

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

    def collect_current(self):
        return {k: self.get_counter(k) for k in OID_MAP.keys()}

    def get_path(self, leaf):
        return f"interfaces/interface[name={self.if_name}]/state/counters/{leaf}"

    def should_emit(self, leaf, value):
        """Decide si emitir según reglas de gNMI (omitir 0 en discards/errors)"""
        if leaf in ['in-discards', 'out-discards', 'in-errors', 'out-errors']:
            return value != "0"  # Solo emitir si ≠ 0
        if leaf in ['in-broadcast-pkts', 'out-broadcast-pkts']:
            return value != "0"  # Opcional: omitir en IPv6 puro
        return True  # Siempre emitir octets, pkts, multicast, carrier

    def generate_updates(self, ts_ns):
        current = self.collect_current()
        updates = []

        # 1. last-update (siempre)
        last_path = f"interfaces/interface[name={self.if_name}]/state/counters/last-update"
        updates.append({
            "Path": last_path,
            "values": {last_path: ts_ns}  # ✅ int64
        })

        # 2. Por cada leaf: emitir solo si cambió y cumple criterio
        for leaf in OID_MAP.keys():
            new_val = current[leaf]
            old_val = self.prev_values[leaf]

            if new_val != old_val and self.should_emit(leaf, new_val):
                path = self.get_path(leaf)
                updates.append({
                    "Path": path,
                    "values": {path: new_val}
                })

        # Actualizar estado
        self.prev_values = current
        return updates


class SNMPPureOnChangeMonitor:
    def __init__(self, target, community):
        try:
            self.session = Session(
                hostname=target,
                community=community,
                version=2,
                timeout=3,
                retries=2
            )
        except EasySNMPError as e:
            print(f"❌ Error SNMP: {e}", file=sys.stderr)
            sys.exit(1)

        # Dos monitores, uno por interfaz
        self.monitor_eth1 = SNMPLeafMonitor(self.session, if_index=1, if_name="Ethernet1")
        self.monitor_eth2 = SNMPLeafMonitor(self.session, if_index=2, if_name="Ethernet2")

    def run(self):
        print("▶ SNMP Monitor — modo *on-change puro* (hoja × hoja)")
        print("  Salida compatible 1:1 con gNMI")
        print("  Ctrl+C para detener\n")

        with open(OUTPUT_FILE, 'w') as f:
            iteration = 0
            while True:
                try:
                    ts = time.time()
                    ts_ns = int(ts * 1e9)

                    all_updates = []
                    all_updates.extend(self.monitor_eth1.generate_updates(ts_ns))
                    all_updates.extend(self.monitor_eth2.generate_updates(ts_ns))

                    for upd in all_updates:
                        json.dump({
                            "source": "router-edge",
                            "subscription-name": "snmp_onchange_pure",
                            "timestamp": ts_ns,
                            "time": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                            "updates": [upd]
                        }, f)
                        f.write("\n")

                    f.flush()

                    # Log resumido (solo cambios visibles)
                    changes = len(all_updates) - 2  # restar 2 × last-update
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"↺ Iter {iteration+1} | {changes} cambios reales emitidos")

                    iteration += 1
                    time.sleep(POLL_INTERVAL)

                except KeyboardInterrupt:
                    print("\n⏹️ Monitoreo detenido.")
                    break
                except Exception as e:
                    print(f"⚠ Error: {e}", file=sys.stderr)
                    time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    monitor = SNMPPureOnChangeMonitor(TARGET, COMMUNITY)
    monitor.run()
