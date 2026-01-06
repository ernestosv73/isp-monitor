#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Monitor — compatible con salida gNMI (OpenConfig/YANG)
Basado en la suscripción a:
  /interfaces/interface[name=Ethernet2]/state/counters

Emite JSON idéntico en estructura al generado por gnmic.
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

INTERFACE_INDEX = 2  # ifIndex de Ethernet2 (confirmado)

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

    # Errors/Discards (32-bit, no HC version)
    'in-discards':         '.1.3.6.1.2.1.2.2.1.13',     # ifInDiscards
    'in-errors':           '.1.3.6.1.2.1.2.2.1.14',     # ifInErrors
    'out-discards':        '.1.3.6.1.2.1.2.2.1.19',     # ifOutDiscards
    'out-errors':          '.1.3.6.1.2.1.2.2.1.20',     # ifOutErrors

    # Otros
    'carrier-transitions': '.1.3.6.1.2.1.2.2.1.9',      # ifAdminStatus change count (proxy)
}

# Campos que deben sumarse para generar pkts totales (como hace gNMI)
PKT_FIELDS_IN = ['in-unicast-pkts', 'in-multicast-pkts', 'in-broadcast-pkts']
PKT_FIELDS_OUT = ['out-unicast-pkts', 'out-multicast-pkts', 'out-broadcast-pkts']


class SNMPMonitorGNMICompat:
    def __init__(self, target, community, if_index):
        self.target = target
        self.community = community
        self.if_index = if_index
        self.session = None
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
        """Obtiene contadores y calcula in-pkts / out-pkts como hace gNMI"""
        raw = {k: self.get_counter(k) for k in OID_MAP.keys()}

        # Calcular totales (como haría YANG/state en gNMI)
        in_pkts = sum(int(raw.get(f, 0)) for f in PKT_FIELDS_IN)
        out_pkts = sum(int(raw.get(f, 0)) for f in PKT_FIELDS_OUT)

        # Añadir totales
        raw['in-pkts'] = str(in_pkts)
        raw['out-pkts'] = str(out_pkts)

        return raw

    def emit_update(self, path, values, ts_ns, prefix=None):
        """Genera un objeto de actualización compatible con gNMI JSON"""
        base = {
            "source": "router-edge",  # Alineado con tu archivo
            "subscription-name": "snmp_interface_stats",
            "timestamp": ts_ns,
            "time": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()
        }
        if prefix:
            base["prefix"] = prefix
            base["updates"] = [
                {"Path": k, "values": {k: v}} for k, v in values.items()
            ]
        else:
            base["updates"] = [
                {"Path": path, "values": {path: values}}
            ]
        return base

    def run(self):
        print("▶ Iniciando monitoreo SNMP (modo gNMI-compat)...")
        print("  Guardando en:", OUTPUT_FILE)
        print("  Ctrl+C para detener\n")

        with open(OUTPUT_FILE, 'w') as f:
            # Opcional: sync-response inicial (descomenta si lo necesitas)
            # sync_msg = {"sync-response": True}
            # json.dump(sync_msg, f)
            # f.write("\n")

            iteration = 0
            while True:
                try:
                    ts = time.time()
                    ts_ns = int(ts * 1e9)

                    counters = self.collect_counters()

                    # 1. last-update (simulado con timestamp local)
                    last_update_path = "interfaces/interface[name=Ethernet2]/state/counters/last-update"
                    #last_update_val = str(int(ts * 1e9))
                    last_update_val = int(ts * 1e9)  # sin str()
                    json.dump(self.emit_update(last_update_path, last_update_val, ts_ns), f)
                    f.write("\n")

                    # 2. carrier-transitions (único, sin prefix)
                    if 'carrier-transitions' in counters:
                        ct_path = "interfaces/interface[name=Ethernet2]/state/counters/carrier-transitions"
                        json.dump(self.emit_update(ct_path, counters['carrier-transitions'], ts_ns), f)
                        f.write("\n")

                    # 3. Grupo de contadores con prefix (como en tu archivo)
                    prefix = "interfaces/interface[name=Ethernet2]/state/counters"
                    batch = {
                        "in-broadcast-pkts": counters['in-broadcast-pkts'],
                        "in-discards": counters['in-discards'],
                        "in-errors": counters['in-errors'],
                        "out-broadcast-pkts": counters['out-broadcast-pkts'],
                        "out-discards": counters['out-discards'],
                        "out-errors": counters['out-errors']
                    }
                    # Solo incluir si hay datos no cero (como hace gNMI)
                    non_zero_batch = {k: v for k, v in batch.items() if v != "0"}
                    if non_zero_batch:
                        json.dump(self.emit_update("", non_zero_batch, ts_ns, prefix=prefix), f)
                        f.write("\n")

                    # 4. in-multicast-pkts (solo cuando cambia o periódico)
                    # En tu archivo aparece como update independiente: lo emulamos
                    json.dump(self.emit_update(
                        "interfaces/interface[name=Ethernet2]/state/counters/in-multicast-pkts",
                        counters['in-multicast-pkts'],
                        ts_ns
                    ), f)
                    f.write("\n")

                    # 5. in-octets, in-pkts, in-unicast-pkts (como bloque)
                    in_block = {
                        "in-octets": counters['in-octets'],
                        "in-pkts": counters['in-pkts'],
                        "in-unicast-pkts": counters['in-unicast-pkts']
                    }
                    json.dump(self.emit_update("", in_block, ts_ns, prefix=prefix), f)
                    f.write("\n")

                    # 6. out-* (análogo)
                    out_block = {
                        "out-multicast-pkts": counters['out-multicast-pkts'],
                        "out-octets": counters['out-octets'],
                        "out-pkts": counters['out-pkts'],
                        "out-unicast-pkts": counters['out-unicast-pkts']
                    }
                    json.dump(self.emit_update("", out_block, ts_ns, prefix=prefix), f)
                    f.write("\n")

                    f.flush()

                    # Log human-readable
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"↺ Iter {iteration+1} | in-octets={counters['in-octets']} "
                          f"| out-octets={counters['out-octets']} "
                          f"| mc-in={counters['in-multicast-pkts']} mc-out={counters['out-multicast-pkts']}")

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
