#!/usr/bin/env python3
"""
Colector SNMP→gNMI optimizado con Single GetRequest.
Version corregida: Get único, métricas reales, sin falsas equivalencias.
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

# Mapeo CORRECTO de OIDs (solo métricas numéricas que existen)
OID_MAP = {
    # High Capacity Counters (64-bit)
    'in-octets': '.1.3.6.1.2.1.31.1.1.1.6',
    'out-octets': '.1.3.6.1.2.1.31.1.1.1.10',
    'in-unicast-pkts': '.1.3.6.1.2.1.31.1.1.1.7',
    'out-unicast-pkts': '.1.3.6.1.2.1.31.1.1.1.11',
    'in-multicast-pkts': '.1.3.6.1.2.1.31.1.1.1.8',
    'out-multicast-pkts': '.1.3.6.1.2.1.31.1.1.1.12',
    'in-broadcast-pkts': '.1.3.6.1.2.1.31.1.1.1.9',      # ✅ NUEVO
    'out-broadcast-pkts': '.1.3.6.1.2.1.31.1.1.1.13',    # ✅ NUEVO
    
    # Basic Interface Counters (32-bit)
    'in-discards': '.1.3.6.1.2.1.2.2.1.13',
    'out-discards': '.1.3.6.1.2.1.2.2.1.19',
    'in-errors': '.1.3.6.1.2.1.2.2.1.14',
    'out-errors': '.1.3.6.1.2.1.2.2.1.20',
    
    # EtherLike-MIB
    'in-fcs-errors': '.1.3.6.1.2.1.10.7.2.1.3',
    
    # Arista IPv6 Counters
    'in-pkts-ipv6': '.1.3.6.1.4.1.30065.3.27.1.1.1.3.2',
    'out-pkts-ipv6': '.1.3.6.1.4.1.30065.3.27.1.1.1.5.2',
}

# Para cálculo de paquetes totales (no hay OID directo)
CALCULATED_METRICS = {
    'in-pkts': ['in-unicast-pkts', 'in-multicast-pkts', 'in-broadcast-pkts'],
    'out-pkts': ['out-unicast-pkts', 'out-multicast-pkts', 'out-broadcast-pkts'],
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class EfficientSNMPCollector:
    """Colector optimizado con Single GetRequest y métricas reales."""
    
    def __init__(self, target: str, community: str):
        self.target = target
        self.community = community
        self.session = None
        self.cycle_count = 0
        self.previous_values = {}  # Para detección de cambios
    
    def connect(self):
        """Conecta una vez y mantiene sesión."""
        if not self.session:
            try:
                self.session = Session(
                    hostname=self.target,
                    community=self.community,
                    version=2,
                    timeout=2,
                    retries=1,
                    use_numeric=True  # Importante: OIDs numéricos
                )
                logger.info(f"Conectado a {self.target}")
            except Exception as e:
                logger.error(f"Error conectando: {e}")
                return False
        return True
    
    def build_single_oid_list(self) -> List[str]:
        """
        Construye una lista de TODOS los OIDs para Single GetRequest.
        
        Returns:
            Lista de OIDs completos con índice de interfaz
        """
        oid_list = []
        
        for if_name, if_index in INTERFACES.items():
            for metric_name, oid_base in OID_MAP.items():
                oid = f"{oid_base}.{if_index}"
                oid_list.append(oid)
        
        logger.debug(f"Total OIDs: {len(oid_list)}")
        return oid_list
    
    def collect_single_request(self) -> Dict[str, Dict[str, int]]:
        """
        Ejecuta un SINGLE GetRequest para todos los OIDs.
        
        Returns:
            Diccionario {if_name: {metric: value}}
        """
        if not self.connect():
            return {}
        
        # Construir lista de OIDs
        oid_list = self.build_single_oid_list()
        
        try:
            # UN SOLO GetRequest para todos los OIDs
            logger.debug(f"Enviando Single GetRequest con {len(oid_list)} OIDs")
            results = self.session.get(oid_list)
            
            # Procesar resultados
            data = self.process_results(oid_list, results)
            
            # Calcular métricas derivadas
            self.calculate_derived_metrics(data)
            
            self.cycle_count += 1
            return data
            
        except Exception as e:
            logger.error(f"Error en GetRequest: {e}")
            return {}
    
    def process_results(self, oid_list: List[str], results: List) -> Dict[str, Dict[str, int]]:
        """Procesa resultados del GetRequest único."""
        data = {if_name: {} for if_name in INTERFACES.keys()}
        
        # Mapear OID a interfaz y métrica
        for i, oid in enumerate(oid_list):
            if i >= len(results):
                break
            
            result = results[i]
            
            # Extraer índice de interfaz del OID
            parts = oid.split('.')
            if_index = int(parts[-1])  # Último componente es el índice
            
            # Encontrar nombre de interfaz
            if_name = None
            for name, idx in INTERFACES.items():
                if idx == if_index:
                    if_name = name
                    break
            
            if not if_name:
                continue
            
            # Determinar métrica
            oid_base = '.'.join(parts[:-1])
            metric_name = None
            for metric, base in OID_MAP.items():
                if base == oid_base:
                    metric_name = metric
                    break
            
            if not metric_name:
                continue
            
            # Convertir valor
            value = 0
            if result.value and result.value != 'NOSUCHINSTANCE':
                try:
                    value = int(result.value)
                except (ValueError, TypeError):
                    # Si no es numérico, podría ser string (como ifName)
                    logger.debug(f"Valor no numérico para {metric_name}: {result.value}")
                    value = 0
            
            data[if_name][metric_name] = value
        
        return data
    
    def calculate_derived_metrics(self, data: Dict[str, Dict[str, int]]):
        """Calcula in-pkts y out-pkts."""
        for if_name in INTERFACES.keys():
            if if_name in data:
                # Calcular in-pkts
                in_total = 0
                for metric in CALCULATED_METRICS['in-pkts']:
                    in_total += data[if_name].get(metric, 0)
                data[if_name]['in-pkts'] = in_total
                
                # Calcular out-pkts
                out_total = 0
                for metric in CALCULATED_METRICS['out-pkts']:
                    out_total += data[if_name].get(metric, 0)
                data[if_name]['out-pkts'] = out_total
    
    def generate_compact_gnmi(self, data: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
        """
        Genera formato gNMI ultra compacto.
        
        Estrategia: 
        - Un objeto por interfaz con TODAS las métricas
        - Solo incluir métricas que cambiaron significativamente
        - sync-response mínimo
        """
        gnmi_lines = []
        now = datetime.now(timezone.utc)
        timestamp_nanos = int(now.timestamp() * 1e9)
        iso_time = f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{now.microsecond:06d}Z"
        
        # Contador de cambios
        total_changes = 0
        
        for if_name in INTERFACES.keys():
            if if_name not in data:
                continue
            
            current_metrics = data[if_name]
            
            # Filtrar solo métricas con valores > 0 o que hayan cambiado
            updates = []
            for metric_name, value in current_metrics.items():
                # Clave para comparar histórico
                cache_key = f"{if_name}_{metric_name}"
                previous = self.previous_values.get(cache_key)
                
                # Determinar si incluir esta métrica:
                # 1. Siempre incluir métricas clave
                # 2. Incluir si cambió significativamente (> 1% o > 1000)
                # 3. Incluir si es primera vez
                
                key_metrics = {'in-octets', 'out-octets', 'in-discards', 'out-discards'}
                should_include = (
                    metric_name in key_metrics or
                    previous is None or
                    value != previous or
                    (previous > 0 and abs(value - previous) > max(1000, previous * 0.01))
                )
                
                if should_include:
                    updates.append({
                        "Path": metric_name,
                        "values": {metric_name: value}
                    })
                    total_changes += 1
                    
                    # Actualizar cache
                    self.previous_values[cache_key] = value
            
            # Solo crear objeto si hay updates
            if updates:
                gnmi_lines.append({
                    "source": "router-edge",
                    "subscription-name": "eos_interface_stats",
                    "timestamp": timestamp_nanos,
                    "time": iso_time,
                    "prefix": f"interfaces/interface[name={if_name}]/state/counters",
                    "updates": updates
                })
        
        # sync-response muy ocasional (cada 100 ciclos)
        if self.cycle_count % 100 == 0:
            gnmi_lines.append({"sync-response": True})
        
        # Log de eficiencia
        if self.cycle_count % 10 == 0:
            logger.info(f"Ciclo {self.cycle_count}: {total_changes} cambios, "
                       f"{len(gnmi_lines)} objetos gNMI")
        
        return gnmi_lines
    
    def save_with_rotation(self, gnmi_lines: List[Dict[str, Any]]):
        """Guarda con rotación automática."""
        try:
            # Append al archivo principal
            with open(OUTPUT_FILE, 'a') as f:
                for line in gnmi_lines:
                    # JSON compacto (sin espacios)
                    f.write(json.dumps(line, separators=(',', ':')) + '\n')
            
            # Rotar si es muy grande (> 50MB)
            if os.path.exists(OUTPUT_FILE):
                size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
                if size_mb > 50:
                    rotated = f"{OUTPUT_FILE}.{int(time.time())}"
                    os.rename(OUTPUT_FILE, rotated)
                    logger.info(f"Archivo rotado: {size_mb:.1f}MB -> {rotated}")
        
        except Exception as e:
            logger.error(f"Error guardando: {e}")
    
    def run_efficient_cycle(self):
        """Ejecuta un ciclo eficiente."""
        start_time = time.time()
        
        # 1. Colectar con Single GetRequest
        data = self.collect_single_request()
        collect_time = time.time() - start_time
        
        if not data:
            logger.warning("Sin datos")
            return
        
        # 2. Generar gNMI compacto
        gnmi_start = time.time()
        gnmi_lines = self.generate_compact_gnmi(data)
        gnmi_time = time.time() - gnmi_start
        
        # 3. Guardar
        save_start = time.time()
        self.save_with_rotation(gnmi_lines)
        save_time = time.time() - save_start
        
        # Métricas de performance
        total_time = time.time() - start_time
        
        if self.cycle_count % 5 == 0:
            logger.info(f"Performance: SNMP={collect_time:.3f}s, "
                       f"gNMI={gnmi_time:.3f}s, Save={save_time:.3f}s, "
                       f"Total={total_time:.3f}s")
        
        return total_time
    
    def run_continuous(self):
        """Ejecuta colección continua optimizada."""
        logger.info("=" * 60)
        logger.info("COLECTOR SNMP→gNMI OPTIMIZADO")
        logger.info(f"Target: {self.target}")
        logger.info(f"Técnica: SINGLE GetRequest por ciclo")
        logger.info(f"Métricas: {len(OID_MAP)} por interfaz")
        logger.info(f"Interfaces: {list(INTERFACES.keys())}")
        logger.info(f"Intervalo: {POLL_INTERVAL}s")
        logger.info(f"Salida: {OUTPUT_FILE}")
        logger.info("=" * 60)
        
        if not self.connect():
            return
        
        # Limpiar archivo al inicio
        if os.path.exists(OUTPUT_FILE):
            os.remove(OUTPUT_FILE)
        
        logger.info("Iniciado. Ctrl+C para detener.\n")
        
        total_cycles = 0
        total_time = 0
        
        try:
            while True:
                cycle_start = time.time()
                
                # Ejecutar ciclo
                cycle_time = self.run_efficient_cycle()
                if cycle_time:
                    total_time += cycle_time
                    total_cycles += 1
                
                # Control preciso del intervalo
                elapsed = time.time() - cycle_start
                sleep_time = max(0.001, POLL_INTERVAL - elapsed)
                
                # Dormir con precisión
                time.sleep(sleep_time)
                
                # Log de eficiencia periódico
                if total_cycles % 20 == 0 and total_cycles > 0:
                    avg_time = total_time / total_cycles
                    efficiency = (1 - (avg_time / POLL_INTERVAL)) * 100
                    logger.info(f"Estadísticas ({total_cycles} ciclos): "
                               f"Avg={avg_time:.3f}s, Eficiencia={efficiency:.1f}%")
                
        except KeyboardInterrupt:
            logger.info("\n" + "=" * 60)
            logger.info("DETENIDO POR USUARIO")
            
            # Estadísticas finales
            if total_cycles > 0:
                avg_time = total_time / total_cycles
                efficiency = (1 - (avg_time / POLL_INTERVAL)) * 100
                logger.info(f"Ciclos completados: {total_cycles}")
                logger.info(f"Tiempo promedio: {avg_time:.3f}s")
                logger.info(f"Eficiencia: {efficiency:.1f}%")
            
            if os.path.exists(OUTPUT_FILE):
                size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
                with open(OUTPUT_FILE, 'r') as f:
                    lines = sum(1 for _ in f)
                logger.info(f"Archivo: {lines} líneas, {size_mb:.2f}MB")
            
            logger.info("=" * 60)


def main():
    """Función principal."""
    collector = EfficientSNMPCollector(TARGET, COMMUNITY)
    collector.run_continuous()


if __name__ == "__main__":
    main()
