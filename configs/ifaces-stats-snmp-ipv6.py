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

# Estándar (HC + IF-MIB + EtherLike-MIB)
STD_OIDS = {
    'in-octets':           '.1.3.6.1.2.1.31.1.1.1.6',
    'out-octets':          '.1.3.6.1.2.1.31.1.1.1.10',
    'in-unicast-pkts':     '.1.3.6.1.2.1.31.1.1.1.7',
    'out-unicast-pkts':    '.1.3.6.1.2.1.31.1.1.1.11',
    'in-multicast-pkts':   '.1.3.6.1.2.1.31.1.1.1.8',
    'out-multicast-pkts':  '.1.3.6.1.2.1.31.1.1.1.12',
    'in-broadcast-pkts':   '.1.3.6.1.2.1.31.1.1.1.9',   # ✅ Añadido
    'out-broadcast-pkts':  '.1.3.6.1.2.1.31.1.1.1.13',  # ✅ Añadido
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
        """Consulta OID con índice de interfaz"""
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

        # --- Métricas IPv6 propietarias (advertencia: solo IPv6) ---
        data['in-pkts'] = self.get_counter(ARISTA_OIDS['in-pkts-ipv6'], if_index)
        data['out-pkts'] = self.get_counter(ARISTA_OIDS['out-pkts-ipv6'], if_index)

        # --- Métricas estándar (HC + IF-MIB + EtherLike) ---
        for key, base_oid in STD_OIDS.items():
            data[key] = self.get_counter(base_oid, if_index)

        return data

    def generate_updates(self, ts_ns):
        updates = []
        for if_name, if_index in self.interfaces:
            current = self.collect_interface(if_name, if_index)
            prev = self.prev_state.get(if_name, {})

            # Detectar cambios (o forzar envío si es la primera iteración)
            changed = {k: v for k, v in current.items() if v != prev.get(k)}
            if not changed and not prev:
                changed = current  # primera vez: enviar todo

            prefix = f"interfaces/interface[name={if_name}]/state/counters"

            # ✅ last-update (siempre, con timestamp del colector)
            updates.append({
                "source": "router-edge",
                "subscription-name": "snmp_interface_stats",
                "timestamp": ts_ns,
                "time": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat(timespec='microseconds').replace('+00:00', '+00:00'),
                "updates": [{
                    "Path": f"{prefix}/last-update",
                    "values": {f"{prefix}/last-update": ts_ns}
                }]
            })

            # ✅ Métricas cambiantes → mapeo directo a paths gNMI/OpenConfig
            gnmipath_map = {
                'in-pkts': 'in-pkts',
                'out-pkts': 'out-pkts',
                'in-octets': 'in-octets',
                'out-octets': 'out-octets',
                'in-unicast-pkts': 'in-unicast-pkts',
                'out-unicast-pkts': 'out-unicast-pkts',
                'in-multicast-pkts': 'in-multicast-pkts',
                'out-multicast-pkts': 'out-multicast-pkts',
                'in-broadcast-pkts': 'in-broadcast-pkts',   # ✅ nuevo
                'out-broadcast-pkts': 'out-broadcast-pkts',  # ✅ nuevo
                'in-discards': 'in-discards',
                'out-discards': 'out-discards',
                'in-errors': 'in-errors',
                'out-errors': 'out-errors',
                'in-fcs-errors': 'in-fcs-errors',
                # ⚠️ 'carrier-transitions' omitido intencionalmente (no usado en datos actuales); descomentar si se quiere
                # 'carrier-transitions': 'carrier-transitions',
            }

            for key, gnmipath in gnmipath_map.items():
                if key in changed:
                    path = f"{prefix}/{gnmipath}"
                    val_raw = changed[key]
                    try:
                        val = int(val_raw) if val_raw.isdigit() else val_raw
                    except (ValueError, TypeError):
                        val = 0
                    updates.append({
                        "source": "router-edge",
                        "subscription-name": "snmp_interface_stats",
                        "timestamp": ts_ns,
                        "time": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat(timespec='microseconds').replace('+00:00', '+00:00'),
                        "updates": [{
                            "Path": path,
                            "values": {path: val}
                        }]
                    })

            self.prev_state[if_name] = current

        return updates


def main():
    print("▶ SNMP Monitor — métricas IPv6 propietarias + HC counters (RFC-compliant)")
    print("  Interfaces: Ethernet1 (ifIndex=1), Ethernet2 (ifIndex=2)")
    print("  Paths compatibles con gNMI/OpenConfig")
    print("  ✅ Incluye in/out-broadcast-pkts (IF-MIB HC)")

    try:
        session = Session(hostname=TARGET, community=COMMUNITY, version=2, timeout=3, retries=2)
        monitor = AristaIPv6Monitor(session)
    except Exception as e:
        print(f"❌ Error al inicializar SNMP: {e}", file=sys.stderr)
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
                print("\n⏹️ Monitoreo detenido por usuario")
                break
            except Exception as e:
                print(f"⚠️ Error en iteración: {e}", file=sys.stderr)
                time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
