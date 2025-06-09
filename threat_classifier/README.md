# 🛡️ Classificador de Ameaças com IA

Sistema inteligente para análise automática de relatórios de incidentes cibernéticos, com extração de IoCs, classificação de ameaças e mapeamento para o framework MITRE ATT&CK.

## 📋 Funcionalidades

- 📥 **Coleta automatizada** de relatórios de fontes públicas
- 📄 **Extração de texto** de PDFs, HTMLs e arquivos de texto
- 🤖 **Análise semântica** usando Large Language Models (LLMs)
- 🎯 **Extração automática de IoCs** (IPs, domínios, URLs, hashes, emails)
- 🔍 **Classificação inteligente** de tipos de ameaça
- ⚔️ **Mapeamento automático** para técnicas MITRE ATT&CK
- 💾 **Armazenamento estruturado** em SQLite e arquivos JSON
- 🌐 **Interface web moderna** usando Streamlit
- 🔎 **Sistema de busca avançado** com múltiplos critérios
- 📊 **Dashboard** com estatísticas e visualizações

## 🏗️ Arquitetura

```
threat_classifier/
├── data/               # Relatórios brutos baixados (PDF/HTML)
├── reports/            # Relatórios processados (texto extraído)
├── processed/          # JSONs estruturados
├── app/                # Código-fonte principal
│   ├── __init__.py
│   ├── collector.py    # Coleta de relatórios
│   ├── extractor.py    # Extração de texto dos relatórios
│   ├── nlp.py          # Interação com LLMs, prompts e parsing
│   ├── database.py     # CRUD para armazenamento dos JSONs
│   ├── interface.py    # Interface de busca (Streamlit)
│   └── utils.py        # Funções utilitárias
├── requirements.txt
├── README.md
├── main.py             # Script principal
└── threat_data.db      # Banco de dados SQLite (criado automaticamente)
```

## 🚀 Instalação e Configuração

### 1. Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### 2. Instalação

```bash
# Clone ou extraia o projeto
cd threat_classifier

# Instale as dependências
pip install -r requirements.txt
```

### 3. Configuração (Opcional)

Para funcionalidades avançadas de IA, configure sua chave da API OpenAI:

```bash
# Linux/Mac
export OPENAI_API_KEY="sua_chave_aqui"

# Windows
set OPENAI_API_KEY=sua_chave_aqui
```

**Nota:** O sistema funciona mesmo sem API key, usando análise baseada em regex.

## 💻 Como Usar

### Opção 1: Interface Web (Recomendado)

```bash
# Inicia a interface web
python main.py --interface

# Acesse no navegador: http://localhost:8501
```

### Opção 2: Pipeline Completo via CLI

```bash
# Executa todo o fluxo automaticamente
python main.py --pipeline
```

### Opção 3: Execução Step-by-Step

```bash
# 1. Coleta de relatórios
python main.py --collect

# 2. Extração de texto
python main.py --extract

# 3. Análise com IA
python main.py --analyze

# 4. Ver estatísticas
python main.py --stats

# 5. Busca interativa
python main.py --search
```

### Opções Avançadas

```bash
# Coleta com URLs específicas
python main.py --collect --urls https://exemplo.com/relatorio1.pdf https://exemplo.com/relatorio2.html

# Execução com logs detalhados
python main.py --pipeline --log-level DEBUG

# Ajuda com todos os comandos
python main.py --help
```

## 🌐 Interface Web

A interface web oferece uma experiência completa com:

### 📊 Dashboard
- Métricas gerais do sistema
- Gráficos de distribuição de ameaças
- Estatísticas de IoCs e técnicas MITRE

### 🔍 Busca de Relatórios
- **Busca por IoC**: Encontre relatórios contendo IPs, domínios, URLs específicas
- **Busca por Tipo de Ameaça**: Filtre por ransomware, APT, phishing, etc.
- **Busca por Técnica MITRE**: Busque por IDs específicos (T1059, T1055, etc.)
- **Busca por Fonte**: Filtre por origem dos relatórios
- **Busca Avançada**: Combine múltiplos critérios

### 📄 Análise de Novos Relatórios
- **Texto Direto**: Cole texto diretamente na interface
- **Upload de Arquivo**: Suporte para PDF, HTML, TXT
- **Download via URL**: Baixe e analise automaticamente

### 📁 Gerenciamento de Arquivos
- Visualize arquivos baixados
- Baixe novos relatórios via URLs
- Estatísticas de armazenamento

## 🔧 Módulos do Sistema

### collector.py
```python
from app.collector import ReportCollector

collector = ReportCollector("data")

# Baixa relatórios de URLs
urls = ["https://exemplo.com/relatorio.pdf"]
arquivos = collector.download_reports(urls)

# Upload manual
arquivo = collector.manual_upload("/path/para/arquivo.pdf")
```

### extractor.py
```python
from app.extractor import TextExtractor

extractor = TextExtractor("reports")

# Extrai texto de PDF
texto = extractor.extract_text_from_pdf("arquivo.pdf")

# Extrai de qualquer tipo suportado
dados = extractor.extract_text_from_file("arquivo.html")
```

### nlp.py
```python
from app.nlp import ThreatAnalyzer

analyzer = ThreatAnalyzer()

# Análise completa
resultado = analyzer.analyze_report(texto, info_fonte)

# Funções específicas
iocs = analyzer.extract_iocs(texto)
tipo = analyzer.classify_threat_type(texto)
mitre = analyzer.extract_mitre_mapping(texto)
```

### database.py
```python
from app.database import ThreatDatabase

db = ThreatDatabase()

# Salva análise
id_relatorio = db.save_analysis(dados_analise)

# Buscas
resultados = db.search_by_ioc("192.168.1.1")
resultados = db.search_by_threat_type("ransomware")
resultados = db.search_by_mitre("T1059")
```

## 📊 Formato de Saída

### Estrutura JSON dos Resultados

```json
{
  "iocs": {
    "ips": ["192.168.1.100", "10.0.0.1"],
    "dominios": ["malicious.com", "bad-domain.org"],
    "urls": ["http://evil.com/payload"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
    "emails": ["attacker@evil.com"]
  },
  "tipo_ameaca": "Ransomware",
  "mitre": [
    {
      "id": "T1059",
      "nome": "Command and Scripting Interpreter",
      "tatica": "Execution"
    }
  ],
  "fonte": "relatorio_exemplo.pdf",
  "data_analise": "2024-01-15 14:30:22",
  "resumo": "Relatório sobre campanha de ransomware...",
  "confianca": 0.85,
  "metadados": {
    "palavras_analisadas": 1250,
    "modelo_usado": "gpt-3.5-turbo",
    "fonte_dados": {...}
  }
}
```

## 🔍 Exemplos de Busca

### Via Interface Web
1. Acesse o dashboard
2. Navegue até "🔍 Buscar Relatórios"
3. Escolha o tipo de busca
4. Insira os critérios
5. Visualize resultados detalhados

### Via CLI Interativo
```bash
python main.py --search

# Exemplo de sessão:
🔍 BUSCA INTERATIVA
Digite 'quit' para sair

Opções de busca:
1. IoC
2. Tipo de Ameaça
3. Técnica MITRE
4. Fonte

Escolha uma opção (1-4) ou 'quit': 1
Digite o IoC: 192.168.1.1

📋 2 resultado(s) encontrado(s):

1. relatorio_apt.pdf
   Tipo: APT
   Confiança: 0.92
   Data: 2024-01-15 10:30:00
   Resumo: Análise de campanha APT direcionada...
```

## 📈 Estatísticas

### Via Interface Web
Acesse a seção "📈 Estatísticas" para visualizar:
- Gráficos interativos de distribuição
- Técnicas MITRE mais frequentes
- Tendências temporais
- Métricas de performance

### Via CLI
```bash
python main.py --stats

📊 ESTATÍSTICAS DO CLASSIFICADOR DE AMEAÇAS
==================================================
📄 Total de Relatórios: 15
🎯 Total de IoCs: 127
⚔️  Técnicas MITRE: 23
🕒 Última Atualização: 2024-01-15 16:45:30

🔥 Tipos de Ameaça Mais Comuns:
   • Ransomware: 5 ocorrências
   • APT: 4 ocorrências
   • Malware: 3 ocorrências

⚔️  Técnicas MITRE Mais Comuns:
   • T1059: 8 ocorrências
   • T1055: 6 ocorrências
   • T1027: 5 ocorrências
```

## 🛠️ Personalização

### Adicionando Novos Tipos de IoC
Edite `app/utils.py` na função `extract_iocs_from_text()`:

```python
# Adicione novos padrões regex
new_pattern = r'seu_regex_aqui'
iocs["novo_tipo"] = re.findall(new_pattern, text)
```

### Customizando Classificação de Ameaças
Modifique `app/nlp.py` na função `_classify_basic_threat()`:

```python
threat_keywords = {
    "Seu_Novo_Tipo": ["palavra1", "palavra2", "palavra3"],
    # ... tipos existentes
}
```

### Adicionando Novos Prompts LLM
Customize os prompts em `app/nlp.py`:

```python
prompt = """
Seu prompt personalizado aqui...
Instruções específicas para o LLM...
"""
```

## 🔧 Troubleshooting

### Problema: "Erro ao conectar com OpenAI"
**Solução**: 
- Verifique sua chave API
- O sistema funcionará com análise básica sem API

### Problema: "Arquivo PDF não foi processado"
**Solução**:
- Verifique se o PyPDF2 está instalado
- Alguns PDFs podem estar protegidos

### Problema: "Interface web não carrega"
**Solução**:
```bash
# Reinstale Streamlit
pip uninstall streamlit
pip install streamlit

# Verifique a porta
python main.py --interface
```

### Problema: "Banco de dados corrompido"
**Solução**:
```bash
# Remova o arquivo do banco (dados serão perdidos)
rm threat_data.db

# Execute novamente
python main.py --pipeline
```

## 📝 Logs

Os logs são salvos em `threat_classifier.log` e incluem:
- Atividades de coleta e extração
- Resultados de análise
- Erros e warnings
- Estatísticas de performance

## 🤝 Contribuições

Contribuições são bem-vindas! Áreas de melhoria:
- Novos extractors (Word, Excel, etc.)
- Integração com mais LLMs (Ollama, Claude, etc.)
- Melhorias na interface
- Novos tipos de análise
- Otimizações de performance

## 📄 Licença

Este projeto é destinado para fins educacionais e de pesquisa em segurança cibernética.

## 🆘 Suporte

Para dúvidas ou problemas:
1. Verifique este README
2. Consulte os logs em `threat_classifier.log`
3. Execute com `--log-level DEBUG` para mais detalhes

---

**Desenvolvido com ❤️ para a comunidade de segurança cibernética** 