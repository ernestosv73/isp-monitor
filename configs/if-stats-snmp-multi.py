#!/usr/bin/env python3
"""
Colector SNMP→gNMI optimizado MULTI-TARGET.
Arquitectura NMS realista: un proceso, múltiples dispositivos.
"""

import json
import time
import logging
import os
from datetime import datetime, timezone
from easysnmp import Session

# ============================================================
# CONFIGURACIÓN GENERAL
# ============================================================

POLL_INTERVAL = 5

TARGETS = [
    {
        "name": "edge-router",
        "target": "172.100.100.7",
        "community": "public",
        "interfaces": {
            "Ethernet1": 1,
            "Ethernet2": 2
        },
        "output": "/data/if-stats-snmp-router.json"
    },
    {
        "name": "core-switch",
        "target": "172.100.100.3",
        "community": "public",
        "interfaces": {
            "ethernet-1/3": 81918,
            "ethernet-1/4": 114686,
            "ethernet-1/5": 147454
        },
        "output": "/data/if-stats-snmp-switch.json"
    }
]

# ============================================================
# OIDs
# ============================================================

OID_MAP = {
    # <<< MOD: ifDescr para equivalencia semántica
    'if-descr': '.1.3.6.1.2.1.2.2.1.2',

    # High Capacity Counters (64-bit)
    'in-octets': '.1.3.6.1.2.1.31.1.1.1.6',
    'out-octets': '.1.3.6.1.2.1.31.1.1.1.10',
    'in-unicast-pkts': '.1.3.6.1.2.1.31.1.1.1.7',
    'out-unicast-pkts': '.1.3.6.1.2.1.31.1.1.1.11',
    'in-multicast-pkts': '.1.3.6.1.2.1.31.1.1.1.8',
    'out-multicast-pkts': '.1.3.6.1.2.1.31.1.1.1.12',
    'in-broadcast-pkts': '.1.3.6.1.2.1.31.1.1.1.9',
    'out-broadcast-pkts': '.1.3.6.1.2.1.31.1.1.1.13',

    # Basic counters
    'in-discards': '.1.3.6.1.2.1.2.2.1.13',
    'out-discards': '.1.3.6.1.2.1.2.2.1.19',
    'in-errors': '.1.3.6.1.2.1.2.2.1.14',
    'out-errors': '.1.3.6.1.2.1.2.2.1.20',

    # EtherLike-MIB
    'in-fcs-errors': '.1.3.6.1.2.1.10.7.2.1.3',
}

CALCULATED_METRICS = {
    'in-pkts': ['in-unicast-pkts', 'in-multicast-pkts', 'in-broadcast-pkts'],
    'out-pkts': ['out-unicast-pkts', 'out-multicast-pkts', 'out-broadcast-pkts'],
}

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================
# CLASE COLECTOR
# ============================================================

class EfficientSNMPCollector:
    def __init__(self, name, target, community, interfaces, output_file):
        self.name = name
        self.target = target
        self.community = community
        self.interfaces = interfaces
        self.output_file = output_file
        self.session = None
        self.previous_values = {}

    def connect(self):
        self.session = Session(
            hostname=self.target,
            community=self.community,
            version=2,
            timeout=2,
            retries=1,
            use_numeric=True
        )
        logger.info(f"[{self.name}] Conectado a {self.target}")

    def build_oid_list(self):
        return [
            f"{oid}.{idx}"
            for idx in self.interfaces.values()
            for oid in OID_MAP.values()
        ]

    def collect(self):
        oid_list = self.build_oid_list()
        results = self.session.get(oid_list)

        data = {ifn: {} for ifn in self.interfaces}

        for oid, res in zip(oid_list, results):
            if res.value == 'NOSUCHINSTANCE':
                continue

            if_index = int(oid.split('.')[-1])
            if_name = next((n for n, i in self.interfaces.items() if i == if_index), None)
            if not if_name:
                continue

            oid_base = '.'.join(oid.split('.')[:-1])
            metric = next((m for m, b in OID_MAP.items() if b == oid_base), None)
            if not metric:
                continue

            if metric == 'if-descr':
                data[if_name]['ifDescr'] = res.value
            else:
                try:
                    data[if_name][metric] = int(res.value)
                except ValueError:
                    data[if_name][metric] = 0

        for ifn in data:
            data[ifn]['in-pkts'] = sum(data[ifn].get(m, 0) for m in CALCULATED_METRICS['in-pkts'])
            data[ifn]['out-pkts'] = sum(data[ifn].get(m, 0) for m in CALCULATED_METRICS['out-pkts'])

        return data

    def generate_gnmi(self, data):
        now = datetime.now(timezone.utc)
        ts = int(now.timestamp() * 1e9)
        iso = now.isoformat()

        lines = []

        for ifn, metrics in data.items():
            updates = []

            for k, v in metrics.items():
                key = f"{ifn}_{k}"

                # <<< MOD: siempre emitir snapshot por interfaz
                updates.append({"Path": k, "values": {k: v}})
                self.previous_values[key] = v

            lines.append({
                "source": self.name,
                "subscription-name": "switch_interface_stats",
                "timestamp": ts,
                "time": iso,
                "prefix": f"interfaces/interface[name={ifn}]/state/counters",
                "updates": updates
            })

        return lines

    def save(self, lines):
        with open(self.output_file, 'a') as f:
            for l in lines:
                f.write(json.dumps(l, separators=(',', ':')) + '\n')

    def run_cycle(self):
        data = self.collect()
        gnmi = self.generate_gnmi(data)
        self.save(gnmi)

# ============================================================
# MAIN
# ============================================================

def main():
    collectors = []

    for t in TARGETS:
        c = EfficientSNMPCollector(
            t["name"], t["target"], t["community"],
            t["interfaces"], t["output"]
        )
        c.connect()
        if os.path.exists(t["output"]):
            os.remove(t["output"])
        collectors.append(c)

    logger.info("NMS SNMP multi-target iniciado")
    logger.info("=" * 60)

    try:
        while True:
            start = time.time()
            for c in collectors:
                c.run_cycle()
            time.sleep(max(0.001, POLL_INTERVAL - (time.time() - start)))

    except KeyboardInterrupt:
        logger.info("Finalizado por usuario")

if __name__ == "__main__":
    main()
