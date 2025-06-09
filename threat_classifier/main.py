"""
Script principal do Classificador de Ameaças com IA
Orquestra todo o fluxo: coleta, extração, análise e interface
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

# Adiciona o diretório app ao path
sys.path.append(str(Path(__file__).parent / "app"))

from app.utils import setup_logging
from app.collector import ReportCollector
from app.extractor import TextExtractor
from app.nlp import ThreatAnalyzer
from app.database import ThreatDatabase
from app.interface import main as run_interface


class ThreatClassifierMain:
    """
    Classe principal para orquestrar o sistema de classificação de ameaças
    """
    
    def __init__(self):
        """
        Inicializa componentes principais
        """
        setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Inicializa componentes
        self.collector = ReportCollector("data")
        self.extractor = TextExtractor("reports")
        self.analyzer = ThreatAnalyzer()
        self.database = ThreatDatabase("threat_data.db", "processed")
        
        self.logger.info("Sistema de classificação de ameaças inicializado")
    
    def collect_reports(self, sources: Optional[List[str]] = None) -> bool:
        """
        Executa coleta de relatórios
        
        Args:
            sources: Lista de URLs para baixar (opcional)
            
        Returns:
            True se sucesso, False caso contrário
        """
        try:
            self.logger.info("Iniciando coleta de relatórios")
            
            if not sources:
                # Usa fontes de exemplo se nenhuma foi fornecida
                sources = self.collector.get_sample_sources()
                self.logger.info("Usando fontes de exemplo")
            
            downloaded_files = self.collector.download_reports(sources)
            
            if downloaded_files:
                self.logger.info(f"Coleta concluída: {len(downloaded_files)} arquivos baixados")
                for file_info in downloaded_files:
                    self.logger.info(f"- {file_info['filename']} ({file_info['size']} bytes)")
                return True
            else:
                self.logger.warning("Nenhum arquivo foi baixado")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro durante coleta: {e}")
            return False
    
    def extract_texts(self) -> bool:
        """
        Extrai texto de todos os arquivos baixados
        
        Returns:
            True se sucesso, False caso contrário
        """
        try:
            self.logger.info("Iniciando extração de textos")
            
            # Lista arquivos na pasta de dados
            files = self.collector.list_downloaded_files()
            
            if not files:
                self.logger.warning("Nenhum arquivo encontrado para extração")
                return False
            
            extracted_count = 0
            
            for file_info in files:
                try:
                    self.logger.info(f"Extraindo texto de: {file_info['filename']}")
                    
                    # Extrai texto
                    extracted_data = self.extractor.extract_text_from_file(file_info['local_path'])
                    
                    if extracted_data:
                        # Salva texto extraído
                        saved_path = self.extractor.save_extracted_text(extracted_data)
                        if saved_path:
                            extracted_count += 1
                            self.logger.info(f"Texto salvo em: {saved_path}")
                    
                except Exception as e:
                    self.logger.error(f"Erro ao extrair {file_info['filename']}: {e}")
                    continue
            
            self.logger.info(f"Extração concluída: {extracted_count} textos extraídos")
            return extracted_count > 0
            
        except Exception as e:
            self.logger.error(f"Erro durante extração: {e}")
            return False
    
    def analyze_reports(self) -> bool:
        """
        Analisa todos os textos extraídos usando IA
        
        Returns:
            True se sucesso, False caso contrário
        """
        try:
            self.logger.info("Iniciando análise de relatórios")
            
            # Lista textos na pasta de reports
            reports_folder = Path("reports")
            if not reports_folder.exists():
                self.logger.warning("Pasta de relatórios não encontrada")
                return False
            
            text_files = list(reports_folder.glob("*.txt"))
            
            if not text_files:
                self.logger.warning("Nenhum arquivo de texto encontrado para análise")
                return False
            
            analyzed_count = 0
            
            for text_file in text_files:
                try:
                    self.logger.info(f"Analisando: {text_file.name}")
                    
                    # Lê o texto
                    with open(text_file, 'r', encoding='utf-8') as f:
                        text_content = f.read()
                    
                    # Informações da fonte
                    source_info = {
                        "filename": text_file.name,
                        "source": "extracted_text"
                    }
                    
                    # Realiza análise
                    analysis_result = self.analyzer.analyze_report(text_content, source_info)
                    
                    # Salva no banco de dados
                    report_id = self.database.save_analysis(analysis_result)
                    
                    if report_id:
                        analyzed_count += 1
                        self.logger.info(f"Análise salva com ID: {report_id}")
                        
                        # Log dos resultados principais
                        self.logger.info(f"  - Tipo de ameaça: {analysis_result['tipo_ameaca']}")
                        self.logger.info(f"  - Confiança: {analysis_result['confianca']:.2f}")
                        
                        total_iocs = sum(len(iocs) for iocs in analysis_result['iocs'].values())
                        self.logger.info(f"  - IoCs encontrados: {total_iocs}")
                        self.logger.info(f"  - Técnicas MITRE: {len(analysis_result['mitre'])}")
                    
                except Exception as e:
                    self.logger.error(f"Erro ao analisar {text_file.name}: {e}")
                    continue
            
            self.logger.info(f"Análise concluída: {analyzed_count} relatórios analisados")
            return analyzed_count > 0
            
        except Exception as e:
            self.logger.error(f"Erro durante análise: {e}")
            return False
    
    def run_full_pipeline(self, sources: Optional[List[str]] = None) -> bool:
        """
        Executa pipeline completo: coleta -> extração -> análise
        
        Args:
            sources: Lista de URLs para baixar (opcional)
            
        Returns:
            True se sucesso, False caso contrário
        """
        self.logger.info("Iniciando pipeline completo")
        
        # 1. Coleta
        if not self.collect_reports(sources):
            self.logger.error("Falha na coleta de relatórios")
            return False
        
        # 2. Extração
        if not self.extract_texts():
            self.logger.error("Falha na extração de textos")
            return False
        
        # 3. Análise
        if not self.analyze_reports():
            self.logger.error("Falha na análise de relatórios")
            return False
        
        self.logger.info("Pipeline completo executado com sucesso!")
        return True
    
    def show_statistics(self):
        """
        Exibe estatísticas do banco de dados
        """
        stats = self.database.get_statistics()
        
        print("\n" + "="*50)
        print("📊 ESTATÍSTICAS DO CLASSIFICADOR DE AMEAÇAS")
        print("="*50)
        
        if stats:
            print(f"📄 Total de Relatórios: {stats['total_reports']}")
            print(f"🎯 Total de IoCs: {stats['total_iocs']}")
            print(f"⚔️  Técnicas MITRE: {stats['total_mitre_techniques']}")
            print(f"🕒 Última Atualização: {stats['last_updated']}")
            
            if stats.get('threat_types'):
                print("\n🔥 Tipos de Ameaça Mais Comuns:")
                for threat in stats['threat_types'][:5]:
                    print(f"   • {threat['tipo']}: {threat['count']} ocorrências")
            
            if stats.get('mitre_techniques'):
                print("\n⚔️  Técnicas MITRE Mais Comuns:")
                for technique in stats['mitre_techniques'][:5]:
                    print(f"   • {technique['id']}: {technique['count']} ocorrências")
        else:
            print("❌ Nenhum dado encontrado no banco")
        
        print("="*50)
    
    def interactive_search(self):
        """
        Interface de busca interativa via CLI
        """
        print("\n🔍 BUSCA INTERATIVA")
        print("Digite 'quit' para sair")
        
        while True:
            print("\nOpções de busca:")
            print("1. IoC")
            print("2. Tipo de Ameaça") 
            print("3. Técnica MITRE")
            print("4. Fonte")
            
            choice = input("\nEscolha uma opção (1-4) ou 'quit': ").strip()
            
            if choice.lower() == 'quit':
                break
            
            results = []
            
            if choice == '1':
                ioc = input("Digite o IoC: ").strip()
                if ioc:
                    results = self.database.search_by_ioc(ioc)
            
            elif choice == '2':
                threat_type = input("Digite o tipo de ameaça: ").strip()
                if threat_type:
                    results = self.database.search_by_threat_type(threat_type)
            
            elif choice == '3':
                mitre_id = input("Digite o ID da técnica MITRE: ").strip()
                if mitre_id:
                    results = self.database.search_by_mitre(mitre_id)
            
            elif choice == '4':
                source = input("Digite o nome da fonte: ").strip()
                if source:
                    results = self.database.search_by_source(source)
            
            else:
                print("❌ Opção inválida")
                continue
            
            # Exibe resultados
            if results:
                print(f"\n📋 {len(results)} resultado(s) encontrado(s):")
                for i, result in enumerate(results, 1):
                    print(f"\n{i}. {result['fonte']}")
                    print(f"   Tipo: {result['tipo_ameaca']}")
                    print(f"   Confiança: {result['confianca']:.2f}")
                    print(f"   Data: {result['data_analise']}")
                    if result['resumo']:
                        print(f"   Resumo: {result['resumo'][:100]}...")
            else:
                print("❌ Nenhum resultado encontrado")


def main():
    """
    Função principal com argumentos de linha de comando
    """
    parser = argparse.ArgumentParser(
        description="Classificador de Ameaças com IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:

  # Pipeline completo
  python main.py --pipeline

  # Apenas coleta
  python main.py --collect

  # Apenas extração
  python main.py --extract

  # Apenas análise
  python main.py --analyze

  # Interface web
  python main.py --interface

  # Busca interativa
  python main.py --search

  # Estatísticas
  python main.py --stats

  # Coleta com URLs específicas
  python main.py --collect --urls https://example.com/report1.pdf https://example.com/report2.html
        """
    )
    
    # Argumentos principais
    parser.add_argument('--pipeline', action='store_true', 
                       help='Executa pipeline completo (coleta + extração + análise)')
    parser.add_argument('--collect', action='store_true', 
                       help='Executa apenas coleta de relatórios')
    parser.add_argument('--extract', action='store_true', 
                       help='Executa apenas extração de texto')
    parser.add_argument('--analyze', action='store_true', 
                       help='Executa apenas análise com IA')
    parser.add_argument('--interface', action='store_true', 
                       help='Inicia interface web')
    parser.add_argument('--search', action='store_true', 
                       help='Busca interativa via CLI')
    parser.add_argument('--stats', action='store_true', 
                       help='Exibe estatísticas')
    
    # Argumentos opcionais
    parser.add_argument('--urls', nargs='+', 
                       help='URLs específicas para coleta')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Nível de log')
    
    args = parser.parse_args()
    
    # Se nenhum argumento foi fornecido, mostra help
    if not any([args.pipeline, args.collect, args.extract, args.analyze, 
                args.interface, args.search, args.stats]):
        parser.print_help()
        return
    
    # Inicializa sistema
    system = ThreatClassifierMain()
    
    try:
        # Executa ações baseadas nos argumentos
        if args.pipeline:
            system.run_full_pipeline(args.urls)
        
        elif args.collect:
            system.collect_reports(args.urls)
        
        elif args.extract:
            system.extract_texts()
        
        elif args.analyze:
            system.analyze_reports()
        
        elif args.interface:
            print("🚀 Iniciando interface web...")
            print("Acesse: http://localhost:8501")
            run_interface()
        
        elif args.search:
            system.interactive_search()
        
        elif args.stats:
            system.show_statistics()
    
    except KeyboardInterrupt:
        print("\n❌ Operação cancelada pelo usuário")
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        logging.error(f"Erro inesperado: {e}", exc_info=True)


if __name__ == "__main__":
    main() 