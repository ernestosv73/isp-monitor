#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP Monitor — modo gNMI-compat con métricas IPv6 propietarias de Arista
- Usa aristaIpIfStatsInPkts[ipv6][ifIndex] y aristaIpIfStatsOutPkts[ipv6][ifIndex]
- Soporta solo Ethernet1 (ifIndex=1) y Ethernet2 (ifIndex=2)
- Estructura idéntica a gnmic (OpenConfig)
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

# 🔧 OIDs propietarios de Arista (IPv6 + ifIndex)
# Formato: base + .2.[ifIndex] → 2 = ipv6, 1/2 = Ethernet1/Ethernet2
ARISTA_OIDS = {
    'in-pkts-ipv6':    '.1.3.6.1.4.1.30065.3.27.1.1.1.3.2',   # + .1, .2
    'out-pkts-ipv6':   '.1.3.6.1.4.1.30065.3.27.1.1.1.5.2',   # + .1, .2
}

# Estándar (HC + IF-MIB) para otras métricas
STD_OIDS = {
    'in-octets':           '.1.3.6.1.2.1.31.1.1.1.6',
    'out-octets':          '.1.3.6.1.2.1.31.1.1.1.10',
    'in-unicast-pkts':     '.1.3.6.1.2.1.31.1.1.1.7',
    'out-unicast-pkts':    '.1.3.6.1.2.1.31.1.1.1.11',
    'in-multicast-pkts':   '.1.3.6.1.2.1.31.1.1.1.8',
    'out-multicast-pkts':  '.1.3.6.1.2.1.31.1.1.1.12',
    'in-discards':         '.1.3.6.1.2.1.2.2.1.13',
    'out-discards':        '.1.3.6.1.2.1.2.2.1.19',
    'in-errors':           '.1.3.6.1.2.1.2.2.1.14',
    'out-errors':          '.1.3.6.1.2.1.2.2.1.20',
    'carrier-transitions': '.1.3.6.1.2.1.2.2.1.9',
    'in-fcs-errors':       '.1.3.6.1.2.1.10.7.2.1.3',  # EtherLike-MIB
}

class AristaIPv6Monitor:
    def __init__(self, session):
        self.session = session
        # Solo interfaces 1 y 2 (Ethernet1, Ethernet2)
        self.interfaces = [("Ethernet1", 1), ("Ethernet2", 2)]
        self.prev_state = {}

    def get_counter(self, oid_base, if_index):
        """Consulta OID Arista con índice IPv6"""
        oid = f"{oid_base}.{if_index}"
        try:
            res = self.session.get(oid)
            if res and res.value and res.value not in ('NOSUCHINSTANCE', 'NOSUCHOBJECT', ''):
                return str(res.value)
        except Exception:
            pass
        return "0"

    def collect_interface(self, if_name, if_index):
        data = {}

        # --- Métricas IPv6 propietarias ---
        data['in-pkts'] = self.get_counter(ARISTA_OIDS['in-pkts-ipv6'], if_index)
        data['out-pkts'] = self.get_counter(ARISTA_OIDS['out-pkts-ipv6'], if_index)

        # --- Métricas estándar (HC + IF-MIB) ---
        for key, base_oid in STD_OIDS.items():
            data[key] = self.get_counter(base_oid, if_index)

        return data

    def generate_updates(self, ts_ns):
        updates = []
        for if_name, if_index in self.interfaces:
            current = self.collect_interface(if_name, if_index)
            prev = self.prev_state.get(if_name, {})

            # Detectar cambios
            changed = {k: v for k, v in current.items() if v != prev.get(k)}
            if not changed and not prev:
                changed = current  # primera vez

            prefix = f"interfaces/interface[name={if_name}]/state/counters"

            # last-update (siempre)
            updates.append({
                "source": "router-edge",
                "subscription-name": "snmp_interface_stats",
                "timestamp": ts_ns,
                "time": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat(),
                "updates": [{
                    "Path": f"{prefix}/last-update",
                    "values": {f"{prefix}/last-update": ts_ns}
                }]
            })

            # Métricas cambiantes (1:1 con gNMI paths)
            for key, val in changed.items():
                # Mapeo directo a OpenConfig gNMI paths
                if key in ['in-pkts', 'out-pkts', 'in-octets', 'out-octets',
                           'in-unicast-pkts', 'out-unicast-pkts',
                           'in-multicast-pkts', 'out-multicast-pkts',
                           'in-discards', 'out-discards',
                           'in-errors', 'out-errors',
                           'in-fcs-errors']:
                    path = f"{prefix}/{key}"
                    # Convertir a int si es numérico
                    val_int = int(val) if val.isdigit() else val
                    updates.append({
                        "source": "router-edge",
                        "subscription-name": "snmp_interface_stats",
                        "timestamp": ts_ns,
                        "time": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat(),
                        "updates": [{
                            "Path": path,
                            "values": {path: val_int}
                        }]
                    })

            self.prev_state[if_name] = current

        return updates


def main():
    print("▶ SNMP Monitor — métricas IPv6 propietarias Arista (RFC-compliant)")
    print("  Interfaces: Ethernet1 (ifIndex=1), Ethernet2 (ifIndex=2)")
    print("  Paths compatibles con gNMI/OpenConfig")

    try:
        session = Session(hostname=TARGET, community=COMMUNITY, version=2, timeout=3, retries=2)
        monitor = AristaIPv6Monitor(session)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return

    with open(OUTPUT_FILE, 'w') as f:
        iteration = 0
        while True:
            try:
                ts = time.time()
                ts_ns = int(ts * 1e9)
                updates = monitor.generate_updates(ts_ns)

                for upd in updates:
                    json.dump(upd, f)
                    f.write("\n")
                f.flush()

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Iter {iteration+1}: {len(updates)} updates")
                iteration += 1
                time.sleep(POLL_INTERVAL)

            except KeyboardInterrupt:
                print("\n⏹️ Monitoreo detenido")
                break
            except Exception as e:
                print(f"⚠️ Error: {e}", file=sys.stderr)
                time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
