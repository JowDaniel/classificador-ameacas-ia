"""
Módulo de banco de dados para o Classificador de Ameaças com IA
Responsável por CRUD, armazenamento de JSONs e consultas estruturadas
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

from .utils import ensure_directory_exists, save_json_file, load_json_file, get_timestamp


class ThreatDatabase:
    """
    Classe responsável pelo gerenciamento de dados de ameaças
    """
    
    def __init__(self, db_path: str = "threat_data.db", processed_folder: str = "processed"):
        """
        Inicializa o banco de dados
        
        Args:
            db_path: Caminho do arquivo do banco SQLite
            processed_folder: Pasta para armazenar JSONs processados
        """
        self.db_path = Path(db_path)
        self.processed_folder = Path(processed_folder)
        ensure_directory_exists(str(self.processed_folder))
        
        self.logger = logging.getLogger(__name__)
        
        # Inicializa o banco de dados
        self._init_database()
    
    def _init_database(self) -> None:
        """
        Inicializa as tabelas do banco de dados
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tabela principal de relatórios
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fonte TEXT NOT NULL,
                        tipo_ameaca TEXT,
                        data_analise TEXT NOT NULL,
                        confianca REAL,
                        resumo TEXT,
                        json_path TEXT UNIQUE,
                        word_count INTEGER,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Tabela de IoCs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS iocs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        report_id INTEGER,
                        tipo TEXT NOT NULL,
                        valor TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (report_id) REFERENCES reports (id),
                        UNIQUE(report_id, tipo, valor)
                    )
                ''')
                
                # Tabela de técnicas MITRE
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS mitre_techniques (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        report_id INTEGER,
                        technique_id TEXT NOT NULL,
                        technique_name TEXT,
                        tactic TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (report_id) REFERENCES reports (id),
                        UNIQUE(report_id, technique_id)
                    )
                ''')
                
                # Índices para otimizar consultas
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_fonte ON reports (fonte)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_tipo ON reports (tipo_ameaca)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_tipo ON iocs (tipo)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_valor ON iocs (valor)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_mitre_id ON mitre_techniques (technique_id)')
                
                conn.commit()
                self.logger.info("Banco de dados inicializado com sucesso")
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro ao inicializar banco de dados: {e}")
            raise
    
    def save_analysis(self, analysis_data: Dict[str, Any]) -> Optional[int]:
        """
        Salva análise completa no banco e arquivo JSON
        
        Args:
            analysis_data: Dados da análise
            
        Returns:
            ID do relatório salvo ou None se erro
        """
        try:
            # Gera nome único para o arquivo JSON
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            fonte_clean = analysis_data["fonte"].replace(" ", "_").replace(".", "_")
            json_filename = f"{fonte_clean}_{timestamp}.json"
            json_path = self.processed_folder / json_filename
            
            # Salva arquivo JSON
            if not save_json_file(analysis_data, str(json_path)):
                return None
            
            # Salva no banco de dados
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insere relatório principal
                cursor.execute('''
                    INSERT INTO reports (
                        fonte, tipo_ameaca, data_analise, confianca, 
                        resumo, json_path, word_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis_data["fonte"],
                    analysis_data["tipo_ameaca"],
                    analysis_data["data_analise"],
                    analysis_data["confianca"],
                    analysis_data["resumo"],
                    str(json_path),
                    analysis_data["metadados"].get("palavras_analisadas", 0)
                ))
                
                report_id = cursor.lastrowid
                
                # Insere IoCs
                for tipo, valores in analysis_data["iocs"].items():
                    for valor in valores:
                        try:
                            cursor.execute('''
                                INSERT OR IGNORE INTO iocs (report_id, tipo, valor)
                                VALUES (?, ?, ?)
                            ''', (report_id, tipo, valor))
                        except sqlite3.Error:
                            continue  # Ignora duplicatas
                
                # Insere técnicas MITRE
                for technique in analysis_data["mitre"]:
                    try:
                        cursor.execute('''
                            INSERT OR IGNORE INTO mitre_techniques 
                            (report_id, technique_id, technique_name, tactic)
                            VALUES (?, ?, ?, ?)
                        ''', (
                            report_id,
                            technique["id"],
                            technique.get("nome", ""),
                            technique.get("tatica", "")
                        ))
                    except sqlite3.Error:
                        continue  # Ignora duplicatas
                
                conn.commit()
                self.logger.info(f"Análise salva com sucesso. ID: {report_id}")
                return report_id
                
        except Exception as e:
            self.logger.error(f"Erro ao salvar análise: {e}")
            return None
    
    def save_json(self, data: Dict[str, Any], file_path: Optional[str] = None) -> bool:
        """
        Salva dados em arquivo JSON
        
        Args:
            data: Dados para salvar
            file_path: Caminho do arquivo (opcional)
            
        Returns:
            True se sucesso, False caso contrário
        """
        if file_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = self.processed_folder / f"report_{timestamp}.json"
        
        return save_json_file(data, str(file_path))
    
    def search_by_ioc(self, ioc: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Busca relatórios por IoC
        
        Args:
            ioc: Valor do IoC
            ioc_type: Tipo do IoC (opcional)
            
        Returns:
            Lista de relatórios encontrados
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                if ioc_type:
                    cursor.execute('''
                        SELECT DISTINCT r.* FROM reports r
                        JOIN iocs i ON r.id = i.report_id
                        WHERE i.valor LIKE ? AND i.tipo = ?
                        ORDER BY r.data_analise DESC
                    ''', (f'%{ioc}%', ioc_type))
                else:
                    cursor.execute('''
                        SELECT DISTINCT r.* FROM reports r
                        JOIN iocs i ON r.id = i.report_id
                        WHERE i.valor LIKE ?
                        ORDER BY r.data_analise DESC
                    ''', (f'%{ioc}%',))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    result['full_data'] = self._load_full_report(result['json_path'])
                    results.append(result)
                
                return results
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro na busca por IoC: {e}")
            return []
    
    def search_by_threat_type(self, threat_type: str) -> List[Dict[str, Any]]:
        """
        Busca relatórios por tipo de ameaça
        
        Args:
            threat_type: Tipo de ameaça
            
        Returns:
            Lista de relatórios encontrados
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM reports
                    WHERE tipo_ameaca LIKE ?
                    ORDER BY data_analise DESC
                ''', (f'%{threat_type}%',))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    result['full_data'] = self._load_full_report(result['json_path'])
                    results.append(result)
                
                return results
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro na busca por tipo de ameaça: {e}")
            return []
    
    def search_by_mitre(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Busca relatórios por técnica MITRE
        
        Args:
            technique_id: ID da técnica MITRE
            
        Returns:
            Lista de relatórios encontrados
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT DISTINCT r.* FROM reports r
                    JOIN mitre_techniques m ON r.id = m.report_id
                    WHERE m.technique_id LIKE ?
                    ORDER BY r.data_analise DESC
                ''', (f'%{technique_id}%',))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    result['full_data'] = self._load_full_report(result['json_path'])
                    results.append(result)
                
                return results
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro na busca por técnica MITRE: {e}")
            return []
    
    def search_by_source(self, source: str) -> List[Dict[str, Any]]:
        """
        Busca relatórios por fonte
        
        Args:
            source: Nome da fonte
            
        Returns:
            Lista de relatórios encontrados
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM reports
                    WHERE fonte LIKE ?
                    ORDER BY data_analise DESC
                ''', (f'%{source}%',))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    result['full_data'] = self._load_full_report(result['json_path'])
                    results.append(result)
                
                return results
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro na busca por fonte: {e}")
            return []
    
    def get_all_reports(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retorna todos os relatórios
        
        Args:
            limit: Limite de resultados
            
        Returns:
            Lista de relatórios
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM reports
                    ORDER BY data_analise DESC
                    LIMIT ?
                ''', (limit,))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    result['full_data'] = self._load_full_report(result['json_path'])
                    results.append(result)
                
                return results
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro ao buscar todos os relatórios: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do banco de dados
        
        Returns:
            Dicionário com estatísticas
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total de relatórios
                cursor.execute('SELECT COUNT(*) FROM reports')
                total_reports = cursor.fetchone()[0]
                
                # Total de IoCs
                cursor.execute('SELECT COUNT(*) FROM iocs')
                total_iocs = cursor.fetchone()[0]
                
                # Total de técnicas MITRE
                cursor.execute('SELECT COUNT(DISTINCT technique_id) FROM mitre_techniques')
                total_mitre = cursor.fetchone()[0]
                
                # Tipos de ameaça mais comuns
                cursor.execute('''
                    SELECT tipo_ameaca, COUNT(*) as count 
                    FROM reports 
                    WHERE tipo_ameaca != 'Não identificado'
                    GROUP BY tipo_ameaca 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                threat_types = [{"tipo": row[0], "count": row[1]} for row in cursor.fetchall()]
                
                # IoCs mais comuns por tipo
                cursor.execute('''
                    SELECT tipo, COUNT(*) as count 
                    FROM iocs 
                    GROUP BY tipo 
                    ORDER BY count DESC
                ''')
                ioc_types = [{"tipo": row[0], "count": row[1]} for row in cursor.fetchall()]
                
                # Técnicas MITRE mais comuns
                cursor.execute('''
                    SELECT technique_id, technique_name, COUNT(*) as count 
                    FROM mitre_techniques 
                    GROUP BY technique_id 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                mitre_techniques = [
                    {"id": row[0], "nome": row[1], "count": row[2]} 
                    for row in cursor.fetchall()
                ]
                
                return {
                    "total_reports": total_reports,
                    "total_iocs": total_iocs,
                    "total_mitre_techniques": total_mitre,
                    "threat_types": threat_types,
                    "ioc_types": ioc_types,
                    "mitre_techniques": mitre_techniques,
                    "last_updated": get_timestamp()
                }
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro ao gerar estatísticas: {e}")
            return {}
    
    def delete_report(self, report_id: int) -> bool:
        """
        Remove um relatório e dados relacionados
        
        Args:
            report_id: ID do relatório
            
        Returns:
            True se sucesso, False caso contrário
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Busca o caminho do JSON
                cursor.execute('SELECT json_path FROM reports WHERE id = ?', (report_id,))
                result = cursor.fetchone()
                
                if result:
                    json_path = result[0]
                    
                    # Remove arquivos relacionados
                    try:
                        Path(json_path).unlink(missing_ok=True)
                    except Exception:
                        pass  # Ignora erros ao deletar arquivo
                    
                    # Remove do banco
                    cursor.execute('DELETE FROM iocs WHERE report_id = ?', (report_id,))
                    cursor.execute('DELETE FROM mitre_techniques WHERE report_id = ?', (report_id,))
                    cursor.execute('DELETE FROM reports WHERE id = ?', (report_id,))
                    
                    conn.commit()
                    self.logger.info(f"Relatório {report_id} removido com sucesso")
                    return True
                
                return False
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro ao remover relatório: {e}")
            return False
    
    def _load_full_report(self, json_path: str) -> Optional[Dict[str, Any]]:
        """
        Carrega dados completos do relatório do arquivo JSON
        
        Args:
            json_path: Caminho do arquivo JSON
            
        Returns:
            Dados completos ou None se erro
        """
        if not json_path or not Path(json_path).exists():
            return None
        
        return load_json_file(json_path)
    
    def get_all_iocs(self) -> List[Dict[str, Any]]:
        """
        Obtém todos os IoCs com informações dos relatórios associados
        
        Returns:
            Lista de IoCs com metadados
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT 
                        i.id,
                        i.tipo,
                        i.valor,
                        i.created_at,
                        r.id as report_id,
                        r.fonte,
                        r.tipo_ameaca,
                        r.confianca,
                        r.data_analise
                    FROM iocs i
                    JOIN reports r ON i.report_id = r.id
                    ORDER BY i.created_at DESC
                ''')
                
                iocs = []
                for row in cursor.fetchall():
                    iocs.append({
                        "id": row[0],
                        "tipo": row[1],
                        "valor": row[2],
                        "created_at": row[3],
                        "report_id": row[4],
                        "fonte": row[5],
                        "tipo_ameaca": row[6],
                        "confianca": row[7],
                        "data_analise": row[8]
                    })
                
                return iocs
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro ao buscar IoCs: {e}")
            return []
    
    def get_iocs_by_type(self, ioc_type: str) -> List[Dict[str, Any]]:
        """
        Obtém IoCs de um tipo específico
        
        Args:
            ioc_type: Tipo de IoC (ips, dominios, urls, hashes, emails)
            
        Returns:
            Lista de IoCs do tipo especificado
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT 
                        i.id,
                        i.tipo,
                        i.valor,
                        i.created_at,
                        r.id as report_id,
                        r.fonte,
                        r.tipo_ameaca,
                        r.confianca,
                        r.data_analise
                    FROM iocs i
                    JOIN reports r ON i.report_id = r.id
                    WHERE i.tipo = ?
                    ORDER BY i.created_at DESC
                ''', (ioc_type,))
                
                iocs = []
                for row in cursor.fetchall():
                    iocs.append({
                        "id": row[0],
                        "tipo": row[1],
                        "valor": row[2],
                        "created_at": row[3],
                        "report_id": row[4],
                        "fonte": row[5],
                        "tipo_ameaca": row[6],
                        "confianca": row[7],
                        "data_analise": row[8]
                    })
                
                return iocs
                
        except sqlite3.Error as e:
            self.logger.error(f"Erro ao buscar IoCs por tipo: {e}")
            return []
    
    def search(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Busca genérica com múltiplos critérios
        
        Args:
            query: Dicionário com critérios de busca
            
        Returns:
            Lista de resultados
        """
        results = []
        
        # Busca por IoC
        if "ioc" in query:
            results.extend(self.search_by_ioc(query["ioc"], query.get("ioc_type")))
        
        # Busca por tipo de ameaça
        if "threat_type" in query:
            results.extend(self.search_by_threat_type(query["threat_type"]))
        
        # Busca por técnica MITRE
        if "mitre" in query:
            results.extend(self.search_by_mitre(query["mitre"]))
        
        # Busca por fonte
        if "source" in query:
            results.extend(self.search_by_source(query["source"]))
        
        # Remove duplicatas mantendo ordem
        seen = set()
        unique_results = []
        for result in results:
            if result["id"] not in seen:
                seen.add(result["id"])
                unique_results.append(result)
        
        return unique_results 