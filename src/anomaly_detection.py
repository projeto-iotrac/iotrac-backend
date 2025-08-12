# anomaly_detection.py
# Sistema de Detecção de Anomalias para IOTRAC
# Detecta sequências suspeitas, analisa padrões de uso e gera alertas
# Dependências: sqlite3, datetime, typing, logging

import sqlite3
import os
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import logging
from collections import defaultdict, Counter
from dataclasses import dataclass
from enum import Enum

from src.config import setup_logging
from src.db_setup import DatabaseManager, DATABASE_PATH
from src.notification_service import notification_service

# Configuração de logging
setup_logging()
logger = logging.getLogger(__name__)

class AnomalyType(str, Enum):
    """Tipos de anomalias detectadas."""
    SUSPICIOUS_SEQUENCE = "suspicious_sequence"
    UNUSUAL_FREQUENCY = "unusual_frequency" 
    UNUSUAL_TIMING = "unusual_timing"
    REPEATED_COMMANDS = "repeated_commands"
    FAILED_COMMANDS_BURST = "failed_commands_burst"

class AlertSeverity(str, Enum):
    """Níveis de severidade dos alertas."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AnomalyRule:
    """Regra de detecção de anomalia."""
    name: str
    anomaly_type: AnomalyType
    threshold: float
    time_window_minutes: int
    severity: AlertSeverity
    enabled: bool = True

@dataclass
class DetectedAnomaly:
    """Anomalia detectada."""
    device_id: int
    anomaly_type: AnomalyType
    severity: AlertSeverity
    description: str
    evidence: Dict[str, Any]
    timestamp: datetime
    rule_name: str

class AnomalyDetectionManager:
    """
    Gerenciador principal de detecção de anomalias.
    Analisa comandos, detecta padrões suspeitos e gera alertas.
    """
    
    def __init__(self, db_path: str = DATABASE_PATH):
        """
        Inicializa o detector de anomalias.
        
        Args:
            db_path (str): Caminho para o banco de dados
        """
        self.db_path = db_path
        self.db_manager = DatabaseManager(db_path)
        self._init_anomaly_tables()
        self._load_default_rules()
    
    def _init_anomaly_tables(self) -> None:
        """
        Cria as tabelas necessárias para detecção de anomalias.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de alertas de anomalias
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT 0,
                    resolved_at TIMESTAMP,
                    resolved_by INTEGER,
                    FOREIGN KEY (device_id) REFERENCES devices (id),
                    FOREIGN KEY (resolved_by) REFERENCES users (id)
                )
            ''')
            
            # Tabela de regras de detecção
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    time_window_minutes INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de estatísticas de uso por dispositivo
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_usage_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    hour_of_day INTEGER NOT NULL,
                    day_of_week INTEGER NOT NULL,
                    command_count INTEGER DEFAULT 0,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(device_id, hour_of_day, day_of_week),
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            # Índices para performance
            cursor.execute('''CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_device_timestamp 
                           ON anomaly_alerts(device_id, timestamp)''')
            cursor.execute('''CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_type_severity 
                           ON anomaly_alerts(anomaly_type, severity)''')
            cursor.execute('''CREATE INDEX IF NOT EXISTS idx_usage_stats_device 
                           ON device_usage_stats(device_id)''')
            
            conn.commit()
            conn.close()
            
            logger.info("Tabelas de detecção de anomalias inicializadas")
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao inicializar tabelas de anomalias: {e}")
            raise
    
    def _load_default_rules(self) -> None:
        """
        Carrega regras padrão de detecção de anomalias.
        """
        default_rules = [
            AnomalyRule(
                name="repeated_commands_burst",
                anomaly_type=AnomalyType.REPEATED_COMMANDS,
                threshold=10,  # 10+ comandos iguais em 5 min
                time_window_minutes=5,
                severity=AlertSeverity.MEDIUM
            ),
            AnomalyRule(
                name="high_frequency_commands", 
                anomaly_type=AnomalyType.UNUSUAL_FREQUENCY,
                threshold=50,  # 50+ comandos em 10 min
                time_window_minutes=10,
                severity=AlertSeverity.HIGH
            ),
            AnomalyRule(
                name="night_usage_anomaly",
                anomaly_type=AnomalyType.UNUSUAL_TIMING,
                threshold=5,  # 5+ comandos entre 2-6h da manhã
                time_window_minutes=60,
                severity=AlertSeverity.MEDIUM
            ),
            AnomalyRule(
                name="failed_commands_burst",
                anomaly_type=AnomalyType.FAILED_COMMANDS_BURST,
                threshold=15,  # 15+ comandos falharam em 5 min
                time_window_minutes=5,
                severity=AlertSeverity.HIGH
            ),
            AnomalyRule(
                name="suspicious_command_sequence",
                anomaly_type=AnomalyType.SUSPICIOUS_SEQUENCE,
                threshold=1,  # Qualquer sequência suspeita
                time_window_minutes=15,
                severity=AlertSeverity.CRITICAL
            )
        ]
        
        # Inserir regras no banco se não existirem
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for rule in default_rules:
            cursor.execute('''
                INSERT OR IGNORE INTO anomaly_rules 
                (name, anomaly_type, threshold, time_window_minutes, severity, enabled)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (rule.name, rule.anomaly_type, rule.threshold, 
                  rule.time_window_minutes, rule.severity, rule.enabled))
        
        conn.commit()
        conn.close()
        
        logger.info("Regras padrão de detecção carregadas")
    
    def analyze_command(self, device_id: int, command: str, status: str, 
                       timestamp: datetime = None) -> List[DetectedAnomaly]:
        """
        Analisa um comando em tempo real e detecta anomalias.
        
        Args:
            device_id (int): ID do dispositivo
            command (str): Comando executado
            status (str): Status do comando (success, error, etc)
            timestamp (datetime): Timestamp do comando
            
        Returns:
            List[DetectedAnomaly]: Lista de anomalias detectadas
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        anomalies = []
        
        try:
            # Atualizar estatísticas de uso
            self._update_usage_stats(device_id, timestamp)
            
            # Executar todas as regras de detecção
            anomalies.extend(self._check_repeated_commands(device_id, command, timestamp))
            anomalies.extend(self._check_frequency_anomaly(device_id, timestamp))
            anomalies.extend(self._check_timing_anomaly(device_id, timestamp))
            anomalies.extend(self._check_failed_commands(device_id, status, timestamp))
            anomalies.extend(self._check_suspicious_sequences(device_id, command, timestamp))
            
            # Salvar anomalias detectadas
            for anomaly in anomalies:
                alert_id = self._save_anomaly_alert(anomaly)
                
                # Enviar email para anomalias de severidade alta ou crítica
                if anomaly.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                    self._send_anomaly_email_alert(anomaly, alert_id)
            
            if anomalies:
                logger.warning(f"Detectadas {len(anomalies)} anomalias para dispositivo {device_id}")
            
        except Exception as e:
            logger.error(f"Erro ao analisar comando: {e}")
        
        return anomalies
    
    def _update_usage_stats(self, device_id: int, timestamp: datetime) -> None:
        """
        Atualiza estatísticas de uso do dispositivo.
        """
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO device_usage_stats (device_id, hour_of_day, day_of_week, command_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(device_id, hour_of_day, day_of_week) 
            DO UPDATE SET 
                command_count = command_count + 1,
                last_updated = CURRENT_TIMESTAMP
        ''', (device_id, hour_of_day, day_of_week))
        
        conn.commit()
        conn.close()
    
    def _check_repeated_commands(self, device_id: int, command: str, 
                               timestamp: datetime) -> List[DetectedAnomaly]:
        """
        Detecta comandos repetidos em sequência suspeita.
        """
        anomalies = []
        
        # Buscar regra
        rule = self._get_rule("repeated_commands_burst")
        if not rule or not rule.enabled:
            return anomalies
        
        # Contar comandos iguais na janela de tempo
        time_window = timestamp - timedelta(minutes=rule.time_window_minutes)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM device_logs 
            WHERE device_id = ? AND command = ? AND timestamp >= ?
        ''', (device_id, command, time_window))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        if count >= rule.threshold:
            anomaly = DetectedAnomaly(
                device_id=device_id,
                anomaly_type=rule.anomaly_type,
                severity=rule.severity,
                description=f"Comando '{command}' repetido {count} vezes em {rule.time_window_minutes} minutos",
                evidence={
                    "command": command,
                    "count": count,
                    "time_window_minutes": rule.time_window_minutes,
                    "threshold": rule.threshold
                },
                timestamp=timestamp,
                rule_name=rule.name
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _check_frequency_anomaly(self, device_id: int, 
                               timestamp: datetime) -> List[DetectedAnomaly]:
        """
        Detecta frequência anormal de comandos.
        """
        anomalies = []
        
        rule = self._get_rule("high_frequency_commands")
        if not rule or not rule.enabled:
            return anomalies
        
        time_window = timestamp - timedelta(minutes=rule.time_window_minutes)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM device_logs 
            WHERE device_id = ? AND timestamp >= ?
        ''', (device_id, time_window))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        if count >= rule.threshold:
            anomaly = DetectedAnomaly(
                device_id=device_id,
                anomaly_type=rule.anomaly_type,
                severity=rule.severity,
                description=f"Frequência alta: {count} comandos em {rule.time_window_minutes} minutos",
                evidence={
                    "count": count,
                    "time_window_minutes": rule.time_window_minutes,
                    "threshold": rule.threshold,
                    "commands_per_minute": round(count / rule.time_window_minutes, 2)
                },
                timestamp=timestamp,
                rule_name=rule.name
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _check_timing_anomaly(self, device_id: int, 
                            timestamp: datetime) -> List[DetectedAnomaly]:
        """
        Detecta uso em horários incomuns.
        """
        anomalies = []
        
        rule = self._get_rule("night_usage_anomaly")
        if not rule or not rule.enabled:
            return anomalies
        
        # Verificar se está no período noturno (2h-6h)
        if not (2 <= timestamp.hour <= 6):
            return anomalies
        
        time_window = timestamp - timedelta(minutes=rule.time_window_minutes)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM device_logs 
            WHERE device_id = ? AND timestamp >= ?
        ''', (device_id, time_window))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        if count >= rule.threshold:
            anomaly = DetectedAnomaly(
                device_id=device_id,
                anomaly_type=rule.anomaly_type,
                severity=rule.severity,
                description=f"Uso noturno suspeito: {count} comandos entre {timestamp.strftime('%H:%M')}",
                evidence={
                    "count": count,
                    "hour": timestamp.hour,
                    "time_window_minutes": rule.time_window_minutes,
                    "threshold": rule.threshold
                },
                timestamp=timestamp,
                rule_name=rule.name
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _check_failed_commands(self, device_id: int, status: str, 
                             timestamp: datetime) -> List[DetectedAnomaly]:
        """
        Detecta rajadas de comandos falhados.
        """
        anomalies = []
        
        rule = self._get_rule("failed_commands_burst")
        if not rule or not rule.enabled or status == "success":
            return anomalies
        
        time_window = timestamp - timedelta(minutes=rule.time_window_minutes)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM device_logs 
            WHERE device_id = ? AND status != 'success' AND timestamp >= ?
        ''', (device_id, time_window))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        if count >= rule.threshold:
            anomaly = DetectedAnomaly(
                device_id=device_id,
                anomaly_type=rule.anomaly_type,
                severity=rule.severity,
                description=f"Rajada de falhas: {count} comandos falharam em {rule.time_window_minutes} minutos",
                evidence={
                    "failed_count": count,
                    "current_status": status,
                    "time_window_minutes": rule.time_window_minutes,
                    "threshold": rule.threshold
                },
                timestamp=timestamp,
                rule_name=rule.name
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _check_suspicious_sequences(self, device_id: int, command: str, 
                                  timestamp: datetime) -> List[DetectedAnomaly]:
        """
        Detecta sequências de comandos suspeitas.
        """
        anomalies = []
        
        rule = self._get_rule("suspicious_command_sequence")
        if not rule or not rule.enabled:
            return anomalies
        
        # Definir sequências suspeitas
        suspicious_patterns = [
            ["emergency_stop", "turn_on", "emergency_stop"],  # Liga e desliga rápido
            ["get_status", "get_status", "get_status", "get_status", "get_status"],  # Muitas consultas
            ["turn_off", "turn_on", "turn_off", "turn_on"],  # Liga/desliga alternado
        ]
        
        time_window = timestamp - timedelta(minutes=rule.time_window_minutes)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Buscar últimos comandos na janela de tempo
        cursor.execute('''
            SELECT command FROM device_logs 
            WHERE device_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC LIMIT 10
        ''', (device_id, time_window))
        
        recent_commands = [row[0] for row in cursor.fetchall()]
        recent_commands.reverse()  # Ordem cronológica
        conn.close()
        
        # Verificar padrões suspeitos
        for pattern in suspicious_patterns:
            if self._sequence_matches_pattern(recent_commands, pattern):
                anomaly = DetectedAnomaly(
                    device_id=device_id,
                    anomaly_type=rule.anomaly_type,
                    severity=rule.severity,
                    description=f"Sequência suspeita detectada: {' -> '.join(pattern)}",
                    evidence={
                        "suspicious_pattern": pattern,
                        "recent_commands": recent_commands[-len(pattern):],
                        "time_window_minutes": rule.time_window_minutes
                    },
                    timestamp=timestamp,
                    rule_name=rule.name
                )
                anomalies.append(anomaly)
                break  # Evitar múltiplos alertas para o mesmo evento
        
        return anomalies
    
    def _sequence_matches_pattern(self, commands: List[str], pattern: List[str]) -> bool:
        """
        Verifica se uma sequência de comandos corresponde a um padrão suspeito.
        """
        if len(commands) < len(pattern):
            return False
        
        # Verificar se os últimos comandos correspondem ao padrão
        recent_sequence = commands[-len(pattern):]
        return recent_sequence == pattern
    
    def _get_rule(self, rule_name: str) -> Optional[AnomalyRule]:
        """
        Busca uma regra de detecção pelo nome.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT name, anomaly_type, threshold, time_window_minutes, severity, enabled
            FROM anomaly_rules WHERE name = ?
        ''', (rule_name,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return AnomalyRule(
                name=row[0],
                anomaly_type=AnomalyType(row[1]),
                threshold=row[2],
                time_window_minutes=row[3],
                severity=AlertSeverity(row[4]),
                enabled=bool(row[5])
            )
        
        return None
    
    def _save_anomaly_alert(self, anomaly: DetectedAnomaly) -> int:
        """
        Salva um alerta de anomalia no banco de dados.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        evidence_json = json.dumps(anomaly.evidence)
        
        cursor.execute('''
            INSERT INTO anomaly_alerts 
            (device_id, anomaly_type, severity, rule_name, description, evidence, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (anomaly.device_id, anomaly.anomaly_type, anomaly.severity,
              anomaly.rule_name, anomaly.description, evidence_json, anomaly.timestamp))
        
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return alert_id
    
    def _send_anomaly_email_alert(self, anomaly: DetectedAnomaly, alert_id: int) -> None:
        """
        Envia alerta de anomalia por email para administradores.
        """
        try:
            # Buscar dispositivo para obter informações
            device = self.db_manager.get_device(anomaly.device_id)
            if not device:
                logger.error(f"Dispositivo {anomaly.device_id} não encontrado para envio de email")
                return
            
            device_type = device.get("device_type", "Desconhecido")
            device_name = device.get("device_name") or f"Dispositivo #{anomaly.device_id}"
            
            # Buscar emails de administradores
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT email, full_name FROM users 
                WHERE role IN ('admin', 'device_operator') AND is_active = 1
            ''')
            
            admin_users = cursor.fetchall()
            conn.close()
            
            if not admin_users:
                logger.warning("Nenhum administrador encontrado para envio de alertas")
                return
            
            # Enviar email para cada administrador
            for email, full_name in admin_users:
                try:
                    success = notification_service.send_anomaly_alert(
                        email=email,
                        anomaly_type=anomaly.anomaly_type,
                        description=anomaly.description,
                        device_id=anomaly.device_id,
                        device_type=device_type,
                        severity=anomaly.severity,
                        user_name=full_name
                    )
                    
                    if success:
                        logger.info(f"Alerta de anomalia #{alert_id} enviado para {email}")
                    else:
                        logger.error(f"Falha ao enviar alerta #{alert_id} para {email}")
                        
                except Exception as e:
                    logger.error(f"Erro ao enviar email de anomalia para {email}: {e}")
            
        except Exception as e:
            logger.error(f"Erro ao processar envio de email de anomalia: {e}")
    
    def get_alerts(self, device_id: Optional[int] = None, 
                   severity: Optional[AlertSeverity] = None,
                   resolved: Optional[bool] = None,
                   limit: int = 100) -> List[Dict[str, Any]]:
        """
        Busca alertas de anomalias com filtros opcionais.
        
        Args:
            device_id: Filtrar por dispositivo específico
            severity: Filtrar por severidade
            resolved: Filtrar por status de resolução
            limit: Limite de resultados
            
        Returns:
            List[Dict]: Lista de alertas
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT a.id, a.device_id, a.anomaly_type, a.severity, a.rule_name,
                   a.description, a.evidence, a.timestamp, a.resolved, a.resolved_at,
                   d.device_type, d.device_name
            FROM anomaly_alerts a
            LEFT JOIN devices d ON a.device_id = d.id
            WHERE 1=1
        '''
        
        params = []
        
        if device_id is not None:
            query += " AND a.device_id = ?"
            params.append(device_id)
        
        if severity is not None:
            query += " AND a.severity = ?"
            params.append(severity)
        
        if resolved is not None:
            query += " AND a.resolved = ?"
            params.append(resolved)
        
        query += " ORDER BY a.timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        alerts = []
        for row in rows:
            alerts.append({
                "id": row[0],
                "device_id": row[1],
                "anomaly_type": row[2],
                "severity": row[3],
                "rule_name": row[4],
                "description": row[5],
                "evidence": json.loads(row[6]) if row[6] else {},
                "timestamp": row[7],
                "resolved": bool(row[8]),
                "resolved_at": row[9],
                "device_type": row[10],
                "device_name": row[11]
            })
        
        return alerts
    
    def resolve_alert(self, alert_id: int, resolved_by: int) -> bool:
        """
        Marca um alerta como resolvido.
        
        Args:
            alert_id: ID do alerta
            resolved_by: ID do usuário que resolveu
            
        Returns:
            bool: True se resolvido com sucesso
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE anomaly_alerts 
            SET resolved = 1, resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
            WHERE id = ? AND resolved = 0
        ''', (resolved_by, alert_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def get_device_usage_patterns(self, device_id: int) -> Dict[str, Any]:
        """
        Retorna padrões de uso de um dispositivo.
        
        Args:
            device_id: ID do dispositivo
            
        Returns:
            Dict: Estatísticas de uso do dispositivo
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Estatísticas por hora
        cursor.execute('''
            SELECT hour_of_day, SUM(command_count) as total_commands
            FROM device_usage_stats 
            WHERE device_id = ?
            GROUP BY hour_of_day
            ORDER BY hour_of_day
        ''', (device_id,))
        
        hourly_stats = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Estatísticas por dia da semana
        cursor.execute('''
            SELECT day_of_week, SUM(command_count) as total_commands
            FROM device_usage_stats 
            WHERE device_id = ?
            GROUP BY day_of_week
            ORDER BY day_of_week
        ''', (device_id,))
        
        daily_stats = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Comandos mais usados
        cursor.execute('''
            SELECT command, COUNT(*) as count
            FROM device_logs 
            WHERE device_id = ?
            GROUP BY command
            ORDER BY count DESC
            LIMIT 10
        ''', (device_id,))
        
        top_commands = [{"command": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "device_id": device_id,
            "hourly_usage": hourly_stats,
            "daily_usage": daily_stats,
            "top_commands": top_commands,
            "total_hours_with_activity": len(hourly_stats),
            "total_days_with_activity": len(daily_stats)
        }

# Instância global do detector
anomaly_detector = AnomalyDetectionManager()

def analyze_command_for_anomalies(device_id: int, command: str, status: str) -> List[DetectedAnomaly]:
    """
    Função utilitária para análise de comandos.
    Para ser chamada pelos interceptadores de comandos.
    """
    return anomaly_detector.analyze_command(device_id, command, status)

def get_anomaly_alerts(device_id: Optional[int] = None, 
                      severity: Optional[str] = None,
                      resolved: Optional[bool] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
    """
    Função utilitária para buscar alertas.
    Para ser usada pelos endpoints da API.
    """
    severity_enum = AlertSeverity(severity) if severity else None
    return anomaly_detector.get_alerts(device_id, severity_enum, resolved, limit) 