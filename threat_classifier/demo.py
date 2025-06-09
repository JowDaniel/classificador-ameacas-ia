#!/usr/bin/env python3
"""
Script de demonstração para o Classificador de Ameaças com IA
Executa um teste completo do sistema com dados de exemplo
"""

import sys
import os
from pathlib import Path

# Adiciona o diretório app ao path
sys.path.append(str(Path(__file__).parent / "app"))

from app.utils import setup_logging
from app.nlp import ThreatAnalyzer
from app.database import ThreatDatabase
import json

def create_sample_reports():
    """
    Cria relatórios de exemplo para demonstração
    """
    sample_reports = [
        {
            "title": "Ransomware LockBit 3.0",
            "content": """
            Análise de Campanha Ransomware LockBit 3.0

            Durante nossa investigação, identificamos uma nova variante do ransomware LockBit 3.0 
            que tem como alvo organizações de saúde. O malware utiliza técnicas avançadas de 
            criptografia e evasão.

            Técnicas MITRE ATT&CK observadas:
            - Initial Access (T1566.001): Spearphishing com anexos maliciosos
            - Execution (T1059.001): PowerShell para execução de scripts  
            - Defense Evasion (T1027): Ofuscação de código
            - Impact (T1486): Criptografia de dados para ransomware

            IoCs Identificados:
            - IP de Command & Control: 192.168.45.123
            - Domínio malicioso: lockbit-payment.onion
            - Hash SHA256: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
            - Email de contato: payment@lockbit-gang.com
            - URL de pagamento: http://lockbit3paymentsxyz.onion/victim123

            O ransomware criptografa arquivos com extensões .txt, .doc, .pdf e exige pagamento 
            em Bitcoin. Recomenda-se implementar monitoramento para os IoCs identificados.
            """
        },
        {
            "title": "APT29 Government Attack",
            "content": """
            Atividade APT29 (Cozy Bear) contra Setor Governamental

            Detectamos atividade consistente com o grupo APT29 em ataques direcionados ao 
            setor governamental. O grupo demonstrou técnicas sofisticadas de persistência e evasão.

            TTPs identificadas:
            - Initial Access (T1078): Contas válidas comprometidas
            - Persistence (T1547.001): Modificação do registro para persistência  
            - Privilege Escalation (T1134): Manipulação de token de acesso
            - Credential Access (T1003.001): Dumping de LSASS
            - Lateral Movement (T1021.001): RDP para movimento lateral

            Indicadores Técnicos:
            - Servidor C2: apt29-command.malicious-domain.com
            - IP suspeito: 10.0.0.45
            - Hash MD5: 5d41402abc4b2a76b9719d911017c592
            - Arquivo malicioso: update_system.exe
            - Registry key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate

            O atacante manteve acesso persistente por aproximadamente 6 meses antes da detecção.
            """
        },
        {
            "title": "Banking Trojan Phishing",
            "content": """
            Campanha de Phishing com Banking Trojan Zeus

            Identificamos uma campanha de phishing direcionada a instituições financeiras 
            utilizando uma variante do Banking Trojan Zeus com capacidades de web injection.

            Cadeia de ataque:
            - Initial Access (T1566.002): Spearphishing via link malicioso
            - Execution (T1204.001): Execução pelo usuário de arquivo malicioso
            - Defense Evasion (T1055): Process injection  
            - Collection (T1005): Coleta de dados do sistema local
            - Exfiltration (T1041): Exfiltração via canal C2

            Indicators of Compromise:
            - Phishing domain: secure-banking-update.net
            - Malicious IP: 203.0.113.42
            - SHA1 hash: da39a3ee5e6b4b0d3255bfef95601890afd80709
            - Fake banking URL: https://fake-bank-login.security-update.org/login
            - Trojan email: security-alert@banking-updates.com

            O malware intercepta credenciais bancárias através de web injects e realiza 
            transações fraudulentas em tempo real.
            """
        }
    ]
    
    return sample_reports

def run_demo():
    """
    Executa demonstração completa do sistema
    """
    print("🛡️  DEMONSTRAÇÃO - CLASSIFICADOR DE AMEAÇAS COM IA")
    print("=" * 60)
    
    # Configura logging
    setup_logging("INFO")
    
    # Inicializa componentes
    print("\n🔧 Inicializando componentes...")
    analyzer = ThreatAnalyzer()
    database = ThreatDatabase()
    
    # Cria relatórios de exemplo
    print("📄 Criando relatórios de exemplo...")
    sample_reports = create_sample_reports()
    
    analyzed_reports = []
    
    # Processa cada relatório
    for i, report in enumerate(sample_reports, 1):
        print(f"\n🤖 Analisando relatório {i}: {report['title']}")
        print("-" * 40)
        
        # Informações da fonte
        source_info = {
            "filename": f"demo_report_{i}.txt",
            "source": "demonstration"
        }
        
        # Analisa relatório
        analysis_result = analyzer.analyze_report(report['content'], source_info)
        
        # Salva no banco
        report_id = database.save_analysis(analysis_result)
        
        if report_id:
            print(f"✅ Relatório salvo com ID: {report_id}")
            
            # Exibe resultados principais
            print(f"📊 Resultados da Análise:")
            print(f"   • Tipo de ameaça: {analysis_result['tipo_ameaca']}")
            print(f"   • Confiança: {analysis_result['confianca']:.2f}")
            
            # Conta IoCs
            total_iocs = sum(len(iocs) for iocs in analysis_result['iocs'].values())
            print(f"   • IoCs encontrados: {total_iocs}")
            
            # Mostra alguns IoCs
            if total_iocs > 0:
                print("   • Principais IoCs:")
                for ioc_type, ioc_list in analysis_result['iocs'].items():
                    if ioc_list:
                        print(f"     - {ioc_type}: {len(ioc_list)} encontrado(s)")
                        for ioc in ioc_list[:3]:  # Mostra até 3
                            print(f"       * {ioc}")
                        if len(ioc_list) > 3:
                            print(f"       * ... e mais {len(ioc_list) - 3}")
            
            # Técnicas MITRE
            print(f"   • Técnicas MITRE: {len(analysis_result['mitre'])}")
            if analysis_result['mitre']:
                print("   • Principais técnicas:")
                for technique in analysis_result['mitre'][:3]:
                    print(f"     - {technique['id']}: {technique.get('nome', 'N/A')}")
                if len(analysis_result['mitre']) > 3:
                    print(f"     - ... e mais {len(analysis_result['mitre']) - 3}")
            
            analyzed_reports.append(analysis_result)
        else:
            print("❌ Erro ao salvar relatório")
    
    # Estatísticas finais
    print(f"\n📈 ESTATÍSTICAS FINAIS")
    print("=" * 60)
    
    stats = database.get_statistics()
    if stats:
        print(f"📄 Total de Relatórios: {stats['total_reports']}")
        print(f"🎯 Total de IoCs: {stats['total_iocs']}")
        print(f"⚔️  Técnicas MITRE: {stats['total_mitre_techniques']}")
        
        if stats.get('threat_types'):
            print(f"\n🔥 Tipos de Ameaça Detectados:")
            for threat in stats['threat_types']:
                print(f"   • {threat['tipo']}: {threat['count']} ocorrência(s)")
    
    # Demonstração de busca
    print(f"\n🔍 DEMONSTRAÇÃO DE BUSCA")
    print("=" * 60)
    
    # Busca por tipo de ameaça
    print("\n1. Buscando relatórios de 'Ransomware':")
    ransomware_results = database.search_by_threat_type("Ransomware")
    print(f"   📋 {len(ransomware_results)} resultado(s) encontrado(s)")
    
    # Busca por IoC
    print("\n2. Buscando relatórios com IP '192.168.45.123':")
    ip_results = database.search_by_ioc("192.168.45.123")
    print(f"   📋 {len(ip_results)} resultado(s) encontrado(s)")
    
    # Busca por técnica MITRE
    print("\n3. Buscando relatórios com técnica 'T1059':")
    mitre_results = database.search_by_mitre("T1059")
    print(f"   📋 {len(mitre_results)} resultado(s) encontrado(s)")
    
    # Instruções finais
    print(f"\n🚀 PRÓXIMOS PASSOS")
    print("=" * 60)
    print("1. Execute a interface web:")
    print("   python main.py --interface")
    print("   Depois acesse: http://localhost:8501")
    print("")
    print("2. Ou explore via linha de comando:")
    print("   python main.py --search")
    print("")
    print("3. Veja estatísticas:")
    print("   python main.py --stats")
    print("")
    print("4. Execute pipeline completo:")
    print("   python main.py --pipeline")
    
    print(f"\n✅ Demonstração concluída com sucesso!")
    print("📊 Dados salvos em: threat_data.db")
    print("📁 Arquivos JSON em: processed/")

def main():
    """
    Função principal
    """
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n❌ Demonstração interrompida pelo usuário")
    except Exception as e:
        print(f"\n❌ Erro durante demonstração: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 