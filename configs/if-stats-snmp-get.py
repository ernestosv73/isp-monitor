#!/usr/bin/env python3
"""
Colector SNMP que genera salida gNMI exacta y acumulativa.
Mantiene todas las consultas en el archivo (append).
"""

import json
import time
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Any
from easysnmp import Session

# Configuración
TARGET = '172.100.100.7'
COMMUNITY = 'public'
POLL_INTERVAL = 5
OUTPUT_FILE = '/data/if-stats-snmp.json'

# Interfaces fijas
INTERFACES = {'Ethernet1': 1, 'Ethernet2': 2}

# Mapeo de OIDs - SOLO LOS QUE TENEMOS REALMENTE
OID_TO_METRIC = {
    # Contadores estándar
    '.1.3.6.1.2.1.31.1.1.1.6': 'in-octets',
    '.1.3.6.1.2.1.31.1.1.1.10': 'out-octets',
    '.1.3.6.1.2.1.31.1.1.1.7': 'in-unicast-pkts',
    '.1.3.6.1.2.1.31.1.1.1.11': 'out-unicast-pkts',
    '.1.3.6.1.2.1.31.1.1.1.8': 'in-multicast-pkts',
    '.1.3.6.1.2.1.31.1.1.1.12': 'out-multicast-pkts',
    '.1.3.6.1.2.1.2.2.1.13': 'in-discards',
    '.1.3.6.1.2.1.2.2.1.19': 'out-discards',
    '.1.3.6.1.2.1.2.2.1.14': 'in-errors',
    '.1.3.6.1.2.1.2.2.1.20': 'out-errors',
    '.1.3.6.1.2.1.10.7.2.1.3': 'in-fcs-errors',
    
    # Métricas IPv6 de Arista
    '.1.3.6.1.4.1.30065.3.27.1.1.1.3.2': 'in-pkts-ipv6',
    '.1.3.6.1.4.1.30065.3.27.1.1.1.5.2': 'out-pkts-ipv6',
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class GNMIFormatCollector:
    """Colector que genera formato gNMI exacto."""
    
    def __init__(self, target: str, community: str):
        self.target = target
        self.community = community
        self.session = None
        self.counter = 0  # Contador para timestamps variados
        self.last_values = {}  # Cache para detectar cambios
        
    def connect(self):
        """Establece conexión SNMP."""
        try:
            self.session = Session(
                hostname=self.target,
                community=self.community,
                version=2,
                timeout=3,
                retries=2
            )
            logger.info(f"Conectado a {self.target}")
            return True
        except Exception as e:
            logger.error(f"Error conectando: {e}")
            return False
    
    def get_gnmi_timestamps(self) -> tuple:
        """
        Genera timestamps en formato gNMI.
        Returns: (timestamp_nanos, iso_time_with_microseconds)
        """
        now = datetime.now(timezone.utc)
        
        # Timestamp en nanosegundos (19 dígitos)
        timestamp_nanos = int(now.timestamp() * 1e9)
        
        # Ajustar ligeramente para cada métrica
        self.counter += 1
        timestamp_variation = timestamp_nanos - (self.counter % 1000)
        
        # ISO time con 7 dígitos de microsegundos como en el ejemplo
        microseconds = now.microsecond
        iso_time = f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{microseconds:06d}0Z"  # 7 dígitos
        
        return timestamp_variation, iso_time
    
    def collect_snmp_data(self) -> Dict[str, Dict[str, int]]:
        """
        Colecta datos SNMP y retorna diccionario {if_name: {metric: value}}.
        """
        if not self.session:
            if not self.connect():
                return {}
        
        # Construir lista de OIDs
        oid_list = []
        for if_name, if_index in INTERFACES.items():
            for oid_base in OID_TO_METRIC.keys():
                oid_list.append(f"{oid_base}.{if_index}")
        
        try:
            # SINGLE GET REQUEST para todos los OIDs
            logger.debug(f"GetRequest con {len(oid_list)} OIDs")
            results = self.session.get(oid_list)
            
            # Procesar resultados
            data = {}
            for if_idx, (if_name, if_index) in enumerate(INTERFACES.items()):
                if if_name not in data:
                    data[if_name] = {}
                
                for metric_idx, (oid_base, metric_name) in enumerate(OID_TO_METRIC.items()):
                    result_idx = (if_idx * len(OID_TO_METRIC)) + metric_idx
                    
                    if result_idx < len(results):
                        result = results[result_idx]
                        if result.value and result.value != 'NOSUCHINSTANCE':
                            try:
                                data[if_name][metric_name] = int(result.value)
                            except:
                                data[if_name][metric_name] = 0
                        else:
                            data[if_name][metric_name] = 0
                    else:
                        data[if_name][metric_name] = 0
            
            return data
            
        except Exception as e:
            logger.error(f"Error en SNMP: {e}")
            return {}
    
    def generate_gnmi_objects(self, data: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
        """
        Genera objetos gNMI en formato exacto.
        
        Estrategia: Mezclar objetos con prefijo y algunos sin prefijo,
        similares al ejemplo original.
        """
        gnmi_objects = []
        
        # Para cada interfaz, crear objeto con PREFIJO (como primera línea del ejemplo)
        for if_name in INTERFACES.keys():
            if if_name in data and data[if_name]:
                # Timestamp principal (para objeto con prefijo)
                timestamp_main, iso_time = self.get_gnmi_timestamps()
                
                # Crear updates para métricas principales (grupo 1)
                main_updates = []
                main_metrics = ['in-octets', 'out-octets', 'in-unicast-pkts', 
                              'out-unicast-pkts', 'in-multicast-pkts', 'out-multicast-pkts']
                
                for metric in main_metrics:
                    if metric in data[if_name]:
                        main_updates.append({
                            "Path": metric,
                            "values": {metric: data[if_name][metric]}
                        })
                
                # Objeto con prefijo (grupo principal de métricas)
                if main_updates:
                    gnmi_objects.append({
                        "source": "router-edge",  # CORREGIDO
                        "subscription-name": "eos_interface_stats",  # CORREGIDO
                        "timestamp": timestamp_main,
                        "time": iso_time,
                        "prefix": f"interfaces/interface[name={if_name}]/state/counters",
                        "updates": main_updates
                    })
                
                # Timestamp para objetos individuales (ligeramente diferente)
                timestamp_individual = timestamp_main - 1000000
                
                # Crear algunos objetos individuales SIN PREFIJO (como en el ejemplo)
                # Solo para métricas que han cambiado
                individual_metrics = ['in-discards', 'out-discards', 'in-errors', 'out-errors']
                
                for metric in individual_metrics:
                    if metric in data[if_name]:
                        current_value = data[if_name][metric]
                        last_value = self.last_values.get(f"{if_name}_{metric}")
                        
                        # Solo generar si cambió o es primera vez
                        if last_value is None or current_value != last_value:
                            gnmi_objects.append({
                                "source": "router-edge",  # CORREGIDO
                                "subscription-name": "eos_interface_stats",  # CORREGIDO
                                "timestamp": timestamp_individual,
                                "time": iso_time,
                                "updates": [{
                                    "Path": f"interfaces/interface[name={if_name}]/state/counters/{metric}",
                                    "values": {
                                        f"interfaces/interface/state/counters/{metric}": current_value
                                    }
                                }]
                            })
                            
                            # Actualizar cache
                            self.last_values[f"{if_name}_{metric}"] = current_value
                
                # Objeto para métricas restantes (grupo 2)
                timestamp_group2 = timestamp_main - 500000
                group2_updates = []
                group2_metrics = ['in-discards', 'out-discards', 'in-errors', 'out-errors', 
                                'in-fcs-errors', 'in-pkts-ipv6', 'out-pkts-ipv6']
                
                for metric in group2_metrics:
                    if metric in data[if_name]:
                        group2_updates.append({
                            "Path": metric,
                            "values": {metric: data[if_name][metric]}
                        })
                
                # Solo agregar si hay métricas en este grupo
                if group2_updates:
                    gnmi_objects.append({
                        "source": "router-edge",  # CORREGIDO
                        "subscription-name": "eos_interface_stats",  # CORREGIDO
                        "timestamp": timestamp_group2,
                        "time": iso_time,
                        "prefix": f"interfaces/interface[name={if_name}]/state/counters",
                        "updates": group2_updates
                    })
        
        # Agregar sync-response solo ocasionalmente (cada 10 ciclos)
        if self.counter % 10 == 0:
            gnmi_objects.append({"sync-response": True})
        
        return gnmi_objects
    
    def append_to_file(self, gnmi_objects: List[Dict[str, Any]]):
        """
        Agrega objetos gNMI al archivo (append mode).
        Mantiene todas las consultas históricas.
        """
        try:
            # Modo append para mantener historial
            with open(OUTPUT_FILE, 'a') as f:
                for obj in gnmi_objects:
                    f.write(json.dumps(obj) + '\n')
            
            logger.info(f"Agregadas {len(gnmi_objects)} líneas al archivo")
            
            # Mostrar estadísticas del archivo
            if os.path.exists(OUTPUT_FILE):
                with open(OUTPUT_FILE, 'r') as f:
                    lines = f.readlines()
                    logger.info(f"Archivo total: {len(lines)} líneas, {os.path.getsize(OUTPUT_FILE)} bytes")
            
        except Exception as e:
            logger.error(f"Error escribiendo archivo: {e}")
    
    def run_collection_cycle(self):
        """Ejecuta un ciclo completo de colección."""
        logger.info(f"--- Ciclo #{self.counter + 1} ---")
        
        # 1. Colectar datos SNMP
        snmp_data = self.collect_snmp_data()
        
        if not snmp_data:
            logger.warning("No se obtuvieron datos SNMP")
            return
        
        # 2. Generar objetos gNMI
        gnmi_objects = self.generate_gnmi_objects(snmp_data)
        
        if not gnmi_objects:
            logger.warning("No se generaron objetos gNMI")
            return
        
        # 3. Agregar al archivo
        self.append_to_file(gnmi_objects)
        
        # 4. Mostrar resumen
        prefixed = sum(1 for obj in gnmi_objects if 'prefix' in obj)
        individual = sum(1 for obj in gnmi_objects if 'prefix' not in obj and 'sync-response' not in obj)
        sync = sum(1 for obj in gnmi_objects if 'sync-response' in obj)
        
        logger.info(f"Resumen: {prefixed} con prefijo, {individual} individuales, {sync} sync-response")
        
        # Mostrar ejemplo de primera línea
        if gnmi_objects:
            first_line = json.dumps(gnmi_objects[0])
            preview = first_line[:150] + "..." if len(first_line) > 150 else first_line
            logger.info(f"Ejemplo: {preview}")
    
    def run_continuous(self):
        """Ejecuta colección continua."""
        logger.info(f"Iniciando colector SNMP→gNMI para {self.target}")
        logger.info(f"Source: router-edge, Subscription: eos_interface_stats")
        logger.info(f"Archivo: {OUTPUT_FILE} (modo append)")
        logger.info(f"Intervalo: {POLL_INTERVAL} segundos")
        
        if not self.connect():
            return
        
        # Limpiar archivo al inicio (opcional)
        if os.path.exists(OUTPUT_FILE):
            backup = f"{OUTPUT_FILE}.bak"
            os.rename(OUTPUT_FILE, backup)
            logger.info(f"Archivo anterior respaldado como {backup}")
        
        logger.info("Colector iniciado. Ctrl+C para detener.")
        
        try:
            while True:
                start_time = time.time()
                
                self.run_collection_cycle()
                
                # Controlar intervalo
                elapsed = time.time() - start_time
                sleep_time = max(0.1, POLL_INTERVAL - elapsed)
                
                if elapsed > POLL_INTERVAL:
                    logger.warning(f"Ciclo tardó {elapsed:.2f}s (> {POLL_INTERVAL}s)")
                
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            logger.info("\nColector detenido por usuario")
            logger.info(f"Archivo final: {OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"Error: {e}")
            raise


def main():
    """Función principal."""
    collector = GNMIFormatCollector(TARGET, COMMUNITY)
    collector.run_continuous()


if __name__ == "__main__":
    main()
