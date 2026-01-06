#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Monitor — modo gNMI-compat + cambio-only
Monitorea simultáneamente Ethernet1 (WAN) y Ethernet2 (Core)
- Usa solo HC counters (64-bit)
- last-update como int64 (compatible con gNMI)
- Solo emite métricas que cambiaron (por interfaz)
- Estructura JSON idéntica a gnmic
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


class SNMPInterfaceMonitor:
    """Monitor para una interfaz específica (ifIndex + nombre)"""
    def __init__(self, session, if_index, if_name):
        self.session = session
        self.if_index = if_index
        self.if_name = if_name
        self.prev_counters = {}

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
        raw = {k: self.get_counter(k) for k in OID_MAP.keys()}
        # Calcular totales
        in_pkts = sum(int(raw.get(f, 0)) for f in ['in-unicast-pkts', 'in-multicast-pkts', 'in-broadcast-pkts'])
        out_pkts = sum(int(raw.get(f, 0)) for f in ['out-unicast-pkts', 'out-multicast-pkts', 'out-broadcast-pkts'])
        raw['in-pkts'] = str(in_pkts)
        raw['out-pkts'] = str(out_pkts)

        # Filtrar cambios
        changed = {k: v for k, v in raw.items() if v != self.prev_counters.get(k)}
        self.prev_counters = raw
        return changed if changed else raw

    def get_path_prefix(self):
        return f"interfaces/interface[name={self.if_name}]/state/counters"

    def emit_update(self, path, values, ts_ns, prefix=None):
        base = {
            "source": "router-edge",
            "subscription-name": "snmp_interface_stats",
            "timestamp": ts_ns,
            "time": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()
        }
        if prefix:
            base["prefix"] = prefix
            if isinstance(values, dict):
                base["updates"] = [{"Path": k, "values": {k: v}} for k, v in values.items()]
            else:
                base["updates"] = [{"Path": path, "values": {path: values}}]
        else:
            base["updates"] = [{"Path": path, "values": {path: values}}]
        return base

    def generate_updates(self, ts_ns):
        """Devuelve lista de updates para esta interfaz (en orden gNMI-style)"""
        counters = self.collect_counters()
        updates = []

        # 1. last-update (siempre)
        last_update_path = f"{self.get_path_prefix()}/last-update"
        updates.append(self.emit_update(last_update_path, ts_ns, ts_ns))

        # 2. carrier-transitions (si presente)
        if 'carrier-transitions' in counters:
            ct_path = f"{self.get_path_prefix()}/carrier-transitions"
            updates.append(self.emit_update(ct_path, counters['carrier-transitions'], ts_ns))

        # 3. Bloques
        # Errors
        error_block = {k: counters[k] for k in ['in-discards', 'in-errors', 'out-discards', 'out-errors'] if k in counters}
        if error_block:
            updates.append(self.emit_update("", error_block, ts_ns, prefix=self.get_path_prefix()))

        # Broadcast (opcional)
        bc_block = {k: counters[k] for k in ['in-broadcast-pkts', 'out-broadcast-pkts'] if k in counters}
        if bc_block:
            updates.append(self.emit_update("", bc_block, ts_ns, prefix=self.get_path_prefix()))

        # in-* block
        in_block = {k: counters[k] for k in ['in-octets', 'in-pkts', 'in-unicast-pkts', 'in-multicast-pkts'] if k in counters}
        if in_block:
            if len(in_block) == 1 and 'in-multicast-pkts' in in_block:
                mc_path = f"{self.get_path_prefix()}/in-multicast-pkts"
                updates.append(self.emit_update(mc_path, in_block['in-multicast-pkts'], ts_ns))
            else:
                updates.append(self.emit_update("", in_block, ts_ns, prefix=self.get_path_prefix()))

        # out-* block
        out_block = {k: counters[k] for k in ['out-octets', 'out-pkts', 'out-unicast-pkts', 'out-multicast-pkts'] if k in counters}
        if out_block:
            if len(out_block) == 1 and 'out-multicast-pkts' in out_block:
                mc_path = f"{self.get_path_prefix()}/out-multicast-pkts"
                updates.append(self.emit_update(mc_path, out_block['out-multicast-pkts'], ts_ns))
            else:
                updates.append(self.emit_update("", out_block, ts_ns, prefix=self.get_path_prefix()))

        return updates


class SNMPDualMonitor:
    def __init__(self, target, community):
        self.target = target
        self.community = community
        self.session = None
        self._init_session()
        # Instanciar monitores por interfaz
        self.monitor_eth1 = SNMPInterfaceMonitor(self.session, if_index=1, if_name="Ethernet1")
        self.monitor_eth2 = SNMPInterfaceMonitor(self.session, if_index=2, if_name="Ethernet2")

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

    def run(self):
        print("▶ Iniciando monitoreo SNMP dual (Ethernet1 + Ethernet2)...")
        print("  Guardando en:", OUTPUT_FILE)
        print("  Ctrl+C para detener\n")

        with open(OUTPUT_FILE, 'w') as f:
            iteration = 0
            while True:
                try:
                    ts = time.time()
                    ts_ns = int(ts * 1e9)

                    # Obtener updates de ambas interfaces
                    all_updates = []
                    all_updates.extend(self.monitor_eth1.generate_updates(ts_ns))
                    all_updates.extend(self.monitor_eth2.generate_updates(ts_ns))

                    # Escribir todos los updates
                    for upd in all_updates:
                        json.dump(upd, f)
                        f.write("\n")
                    f.flush()

                    # Log resumido
                    # Nota: para simplificar, tomamos los últimos valores conocidos (pueden ser anteriores si no cambiaron)
                    eth1_in = self.monitor_eth1.prev_counters.get('in-octets', '—')
                    eth1_out = self.monitor_eth1.prev_counters.get('out-octets', '—')
                    eth2_in = self.monitor_eth2.prev_counters.get('in-octets', '—')
                    eth2_out = self.monitor_eth2.prev_counters.get('out-octets', '—')
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"↻ Iter {iteration+1} | "
                          f"E1:in={eth1_in} out={eth1_out} | "
                          f"E2:in={eth2_in} out={eth2_out}")

                    iteration += 1
                    time.sleep(POLL_INTERVAL)

                except KeyboardInterrupt:
                    print("\n⏹️ Monitoreo detenido por usuario.")
                    break
                except Exception as e:
                    print(f"⚠ Error en iteración: {e}", file=sys.stderr)
                    time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    monitor = SNMPDualMonitor(TARGET, COMMUNITY)
    monitor.run()
