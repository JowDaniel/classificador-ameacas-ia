"""
Módulo de interface para o Classificador de Ameaças com IA
Interface web usando Streamlit para busca e visualização de dados
"""

import streamlit as st
import pandas as pd
import json
import logging
from typing import Dict, List, Any, Optional
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import time

# Imports locais
from .database import ThreatDatabase
from .nlp import ThreatAnalyzer
from .extractor import TextExtractor
from .collector import ReportCollector
from .auto_collector import AutoCollector
from .utils import setup_logging


class ThreatInterface:
    """
    Classe da interface web para o sistema de classificação de ameaças
    """
    
    def __init__(self):
        """
        Inicializa a interface
        """
        self.db = ThreatDatabase()
        self.nlp = ThreatAnalyzer()
        self.extractor = TextExtractor()
        self.collector = ReportCollector()
        self.auto_collector = AutoCollector(self.db, self.nlp)
        
        # Configura logging
        setup_logging()
        self.logger = logging.getLogger(__name__)
    
    def main(self):
        """
        Função principal da interface
        """
        st.set_page_config(
            page_title="Classificador de Ameaças com IA",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # CSS personalizado
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .metric-card {
            background: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .threat-high { color: #dc3545; font-weight: bold; }
        .threat-medium { color: #fd7e14; font-weight: bold; }
        .threat-low { color: #28a745; font-weight: bold; }
        .ioc-tag {
            background-color: #f1f3f4;
            border: 1px solid #dadce0;
            border-radius: 8px;
            padding: 4px 8px;
            margin: 2px;
            display: inline-block;
            font-family: monospace;
            font-size: 0.85em;
            color: #333;
        }
        .ioc-table {
            font-family: 'Courier New', monospace;
        }
        .filter-section {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #e9ecef;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Header principal
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Classificador de Ameaças com IA</h1>
            <p>Sistema de análise e classificação automática de relatórios de incidentes cibernéticos</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Sidebar com navegação
        st.sidebar.header("🛡️ Classificador de Ameaças")
        
        page = st.sidebar.selectbox(
            "📋 Navegação:",
            [
                "📊 Dashboard e Estatísticas",
                "📄 Analisar Novo Relatório", 
                "📁 Gerenciar e Buscar Relatórios",
                "🤖 Coleta Automática"
            ]
        )
        
        # Roteamento das páginas
        if page == "📊 Dashboard e Estatísticas":
            self.show_dashboard_and_statistics()
        elif page == "📄 Analisar Novo Relatório":
            self.show_analysis_page()
        elif page == "📁 Gerenciar e Buscar Relatórios":
            self.show_management_and_search()
        elif page == "🤖 Coleta Automática":
            self.show_auto_collection_page()
    
    def show_dashboard_and_statistics(self):
        """
        Página combinada de Dashboard e Estatísticas Detalhadas
        """
        st.header("📊 Dashboard e Estatísticas")
        
        # Tabs para organizar o conteúdo
        tab1, tab2 = st.tabs(["📊 Dashboard Geral", "📈 Estatísticas Detalhadas"])
        
        with tab1:
            self.show_dashboard()
        
        with tab2:
            self.show_individual_statistics()
    
    def show_dashboard(self):
        """
        Página do dashboard principal
        """
        # st.header("📊 Dashboard Geral")  # Removido para evitar duplicação
        
        # Obtém estatísticas
        stats = self.db.get_statistics()
        
        if stats:
            # Métricas principais
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    "Total de Relatórios",
                    stats.get("total_reports", 0),
                    delta="📄"
                )
            
            with col2:
                st.metric(
                    "IoCs Identificados",
                    stats.get("total_iocs", 0),
                    delta="🎯"
                )
            
            with col3:
                st.metric(
                    "Técnicas MITRE",
                    stats.get("total_mitre_techniques", 0),
                    delta="⚔️"
                )
            
            with col4:
                st.metric(
                    "Última Atualização",
                    stats.get("last_updated", "N/A")[:10],  # Apenas a data
                    delta="🕒"
                )
            
            # Gráficos
            col1, col2 = st.columns(2)
            
            with col1:
                if stats.get("threat_types"):
                    st.subheader("🎯 Tipos de Ameaça Mais Comuns")
                    threat_df = pd.DataFrame(stats["threat_types"])
                    fig = px.pie(
                        threat_df, 
                        values='count', 
                        names='tipo',
                        title="Distribuição de Tipos de Ameaça"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                if stats.get("ioc_types"):
                    st.subheader("🔍 Tipos de IoC Mais Comuns")
                    ioc_df = pd.DataFrame(stats["ioc_types"])
                    fig = px.bar(
                        ioc_df, 
                        x='tipo', 
                        y='count',
                        title="Quantidade de IoCs por Tipo"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            # Técnicas MITRE mais comuns
            if stats.get("mitre_techniques"):
                st.subheader("⚔️ Técnicas MITRE ATT&CK Mais Comuns")
                mitre_df = pd.DataFrame(stats["mitre_techniques"][:10])  # Top 10
                
                # Adiciona nomes das técnicas
                from .utils import get_mitre_technique_name
                mitre_df['nome_tecnica'] = mitre_df['id'].apply(get_mitre_technique_name)
                
                fig = px.bar(
                    mitre_df, 
                    x='count', 
                    y='nome_tecnica',
                    orientation='h',
                    title="Top 10 Técnicas MITRE ATT&CK",
                    hover_data=['id'],
                    color='count',
                    color_continuous_scale='Reds'
                )
                fig.update_layout(
                    yaxis_title="Técnica MITRE",
                    xaxis_title="Quantidade",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
        
            # Seção de IoCs
            st.divider()
            st.subheader("🎯 Tabela de Indicadores de Compromisso (IoCs)")
            
            # Obtém todos os IoCs
            all_iocs = self.db.get_all_iocs()
            
            if all_iocs:
                # Cria DataFrame dos IoCs
                iocs_df = pd.DataFrame(all_iocs)
                
                # Filtros
                col1, col2, col3 = st.columns([2, 2, 4])
                
                with col1:
                    # Filtro por tipo de IoC
                    ioc_types = ["Todos"] + sorted(list(iocs_df['tipo'].unique()))
                    selected_ioc_type = st.selectbox(
                        "🔍 Filtrar por Tipo de IoC:",
                        ioc_types,
                        help="Filtre por tipo específico de IoC"
                    )
                
                with col2:
                    # Filtro por tipo de ameaça
                    threat_types = ["Todos"] + sorted(list(iocs_df['tipo_ameaca'].unique()))
                    selected_threat_type = st.selectbox(
                        "⚠️ Filtrar por Tipo de Ameaça:",
                        threat_types,
                        help="Filtre por tipo de ameaça"
                    )
                
                with col3:
                    # Campo de busca por valor
                    search_value = st.text_input(
                        "🔎 Buscar por Valor:",
                        placeholder="Digite parte do IoC (IP, domínio, hash...)",
                        help="Busque por qualquer parte do valor do IoC"
                    )
                
                # Aplica filtros
                filtered_iocs = iocs_df.copy()
                
                if selected_ioc_type != "Todos":
                    filtered_iocs = filtered_iocs[filtered_iocs['tipo'] == selected_ioc_type]
                
                if selected_threat_type != "Todos":
                    filtered_iocs = filtered_iocs[filtered_iocs['tipo_ameaca'] == selected_threat_type]
                
                if search_value:
                    filtered_iocs = filtered_iocs[
                        filtered_iocs['valor'].str.contains(search_value, case=False, na=False)
                    ]
                
                # Informações dos filtros
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total de IoCs", len(iocs_df))
                with col2:
                    st.metric("IoCs Filtrados", len(filtered_iocs))
                with col3:
                    if len(filtered_iocs) > 0:
                        unique_sources = filtered_iocs['fonte'].nunique()
                        st.metric("Fontes Únicas", unique_sources)
                
                # Tabela de IoCs
                if not filtered_iocs.empty:
                    # Prepara DataFrame para exibição
                    display_df = filtered_iocs.copy()
                    
                    # Formatação das colunas
                    display_df['confianca_fmt'] = display_df['confianca'].apply(lambda x: f"{x:.2f}")
                    display_df['data_fmt'] = pd.to_datetime(display_df['data_analise']).dt.strftime('%d/%m/%Y %H:%M')
                    
                    # Adiciona ícones por tipo de IoC
                    ioc_icons = {
                        'ips': '🌐',
                        'dominios': '🔗',
                        'urls': '🌍',
                        'hashes': '#️⃣',
                        'emails': '📧',
                        'arquivos': '📄',
                        'registry': '🗂️',
                        'mutexes': '🔒',
                        'processos': '⚙️'
                    }
                    
                    display_df['tipo_icon'] = display_df['tipo'].apply(lambda x: f"{ioc_icons.get(x, '📊')} {x.title()}")
                    
                    # Tabela interativa
                    st.dataframe(
                        display_df[['tipo_icon', 'valor', 'tipo_ameaca', 'confianca_fmt', 'fonte', 'data_fmt']],
                        column_config={
                            'tipo_icon': 'Tipo',
                            'valor': st.column_config.TextColumn(
                                'Valor do IoC',
                                width='large'
                            ),
                            'tipo_ameaca': 'Tipo de Ameaça',
                            'confianca_fmt': st.column_config.NumberColumn(
                                'Confiança',
                                format="%.2f"
                            ),
                            'fonte': st.column_config.TextColumn(
                                'Fonte',
                                width='medium'
                            ),
                            'data_fmt': 'Data da Análise'
                        },
                        use_container_width=True,
                        hide_index=True,
                        height=400
                    )
                    
                    # Ações em lote
                    st.subheader("🔧 Ações")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("📥 Exportar IoCs Filtrados"):
                            # Prepara dados para exportação
                            export_df = filtered_iocs[['tipo', 'valor', 'tipo_ameaca', 'fonte', 'data_analise', 'confianca']]
                            csv_data = export_df.to_csv(index=False, encoding='utf-8')
                            
                            st.download_button(
                                label="📁 Download CSV",
                                data=csv_data,
                                file_name=f"iocs_filtrados_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                    
                    with col2:
                        if st.button("📊 Estatísticas dos IoCs"):
                            # Mostra estatísticas detalhadas
                            st.write("**📈 Distribuição por Tipo:**")
                            type_counts = filtered_iocs['tipo'].value_counts()
                            
                            fig_types = px.pie(
                                values=type_counts.values,
                                names=type_counts.index,
                                title="Distribuição de IoCs por Tipo"
                            )
                            st.plotly_chart(fig_types, use_container_width=True)
                    
                    with col3:
                        if st.button("🔗 Ver Relatórios Relacionados"):
                            # Lista relatórios únicos dos IoCs filtrados
                            unique_reports = filtered_iocs[['report_id', 'fonte', 'tipo_ameaca']].drop_duplicates()
                            st.write(f"**📄 {len(unique_reports)} Relatório(s) Relacionado(s):**")
                            
                            for _, report in unique_reports.iterrows():
                                with st.expander(f"📋 ID {report['report_id']} - {report['fonte'][:50]}..."):
                                    st.write(f"**Tipo de Ameaça:** {report['tipo_ameaca']}")
                                    
                                    # IoCs específicos deste relatório
                                    report_iocs = filtered_iocs[filtered_iocs['report_id'] == report['report_id']]
                                    st.write(f"**IoCs neste relatório:** {len(report_iocs)}")
                                    
                                    # Agrupa por tipo
                                    for ioc_type in report_iocs['tipo'].unique():
                                        type_iocs = report_iocs[report_iocs['tipo'] == ioc_type]['valor'].tolist()
                                        st.write(f"• **{ioc_type.title()}:** {len(type_iocs)} IoC(s)")
                                        for ioc in type_iocs[:5]:  # Mostra apenas os primeiros 5
                                            st.markdown(f"""
                                            <span class="ioc-tag">{ioc}</span>
                                            """, unsafe_allow_html=True)
                                        if len(type_iocs) > 5:
                                            st.caption(f"... e mais {len(type_iocs) - 5} {ioc_type}")
                
                else:
                    st.warning("❌ Nenhum IoC encontrado com os filtros aplicados.")
                    
                    # Sugestões quando não há resultados
                    st.info("💡 **Sugestões:**")
                    st.write("• Remova alguns filtros para ver mais resultados")
                    st.write("• Verifique se há análises realizadas")
                    st.write("• Use a seção 'Analisar Novo Relatório' para adicionar dados")
            
            else:
                st.info("📂 Nenhum IoC encontrado na base de dados.")
                st.write("Para ver IoCs aqui:")
                st.write("• Analise relatórios de segurança")
                st.write("• Faça upload de documentos com indicadores")
                st.write("• Use URLs de relatórios técnicos")
        
        else:
            st.info("📝 Nenhum relatório analisado ainda. Comece adicionando alguns relatórios!")
    
    def show_management_and_search(self):
        """
        Página combinada de busca e gerenciamento de relatórios
        """
        st.header("🔍 Gerenciar e Buscar Relatórios")
        
        # Obtém todos os relatórios
        all_reports = self.db.get_all_reports(limit=1000)
        
        if all_reports:
            # Seção de busca e filtros
            st.subheader("🔍 Busca e Filtros")
            
            # Converte para DataFrame
            df_reports = pd.DataFrame(all_reports)
            
            # Filtros em linha
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                # Filtro por tipo de ameaça
                threat_types = ["Todos"] + sorted(list(df_reports['tipo_ameaca'].unique()))
                selected_threat = st.selectbox("🎯 Tipo de Ameaça:", threat_types)
            
            with col2:
                # Filtro por IoC
                ioc_search = st.text_input("🔍 Buscar por IoC:", placeholder="Ex: 192.168.1.1")
            
            with col3:
                # Filtro por técnica MITRE
                mitre_search = st.text_input("⚔️ Técnica MITRE:", placeholder="Ex: T1566")
            
            with col4:
                # Filtro por fonte
                source_search = st.text_input("📄 Buscar na Fonte:", placeholder="Ex: parte do nome")
            
            # Aplicar filtros
            filtered_reports = df_reports.copy()
            
            if selected_threat != "Todos":
                filtered_reports = filtered_reports[filtered_reports['tipo_ameaca'] == selected_threat]
            
            if ioc_search:
                # Busca em IoCs usando o banco
                ioc_reports = self.db.search_by_ioc(ioc_search)
                ioc_ids = [r['id'] for r in ioc_reports]
                filtered_reports = filtered_reports[filtered_reports['id'].isin(ioc_ids)]
            
            if mitre_search:
                # Busca em técnicas MITRE usando o banco
                mitre_reports = self.db.search_by_mitre(mitre_search)
                mitre_ids = [r['id'] for r in mitre_reports]
                filtered_reports = filtered_reports[filtered_reports['id'].isin(mitre_ids)]
            
            if source_search:
                # Busca por fonte
                filtered_reports = filtered_reports[
                    filtered_reports['fonte'].str.contains(source_search, case=False, na=False)
                ]
            
            # Informações dos filtros
            st.info(f"📋 {len(filtered_reports)} de {len(df_reports)} análise(s) encontrada(s)")
            
            # Seção de resultados e gerenciamento
            st.divider()
            st.subheader("📋 Relatórios Encontrados")
            
            if not filtered_reports.empty:
                # Seletor de relatório
                report_options = []
                for _, report in filtered_reports.iterrows():
                    fonte_display = report['fonte']
                    if len(fonte_display) > 60:
                        fonte_display = fonte_display[:57] + "..."
                    
                    option_text = f"ID {report['id']} - {fonte_display} [{report['tipo_ameaca']}]"
                    report_options.append(option_text)
                
                selected_option = st.selectbox(
                    "📄 Selecione um relatório para gerenciar:",
                    ["Nenhum selecionado"] + report_options
                )
                
                if selected_option != "Nenhum selecionado":
                    # Extrai o ID do relatório selecionado
                    report_id = int(selected_option.split("ID ")[1].split(" -")[0])
                    selected_report = filtered_reports[filtered_reports['id'] == report_id].iloc[0]
                    
                    # Exibe detalhes do relatório selecionado
                    st.divider()
                    st.subheader(f"📄 Detalhes da Análise - ID {report_id}")
                    
                    # Informações básicas em colunas
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("🎯 Tipo de Ameaça", selected_report['tipo_ameaca'])
                        st.write(f"**📅 Data da Análise:** {selected_report['data_analise']}")
                    
                    with col2:
                        st.metric("🎯 Confiança", f"{selected_report['confianca']:.2f}")
                        
                        def get_source_type(fonte):
                            if fonte.startswith('http'):
                                return "🌐 URL"
                            elif fonte == "texto_direto.txt":
                                return "📝 Texto Direto"
                            else:
                                return "📁 Arquivo"
                        
                        source_type = get_source_type(selected_report['fonte'])
                        st.write(f"**📂 Tipo:** {source_type}")
                    
                    with col3:
                        if selected_report.get('json_path'):
                            full_data = self.db._load_full_report(selected_report['json_path'])
                            if full_data:
                                total_iocs = sum(len(iocs) for iocs in full_data.get('iocs', {}).values())
                                mitre_count = len(full_data.get('mitre', []))
                                
                                st.metric("🎯 IoCs Encontrados", total_iocs)
                                st.metric("⚔️ Técnicas MITRE", mitre_count)
                    
                    # Fonte completa
                    st.write(f"**📄 Fonte:**")
                    st.code(selected_report['fonte'])
                    
                    # Carrega dados completos para exibição detalhada
                    if selected_report.get('json_path'):
                        full_data = self.db._load_full_report(selected_report['json_path'])
                        if full_data:
                            # Tabs para organizar informações
                            tab1, tab2, tab3, tab4 = st.tabs(["📝 Resumo", "🎯 IoCs", "⚔️ MITRE", "📥 Ações"])
                            
                            with tab1:
                                if full_data.get('resumo'):
                                    st.write("**📋 Resumo da Análise:**")
                                    st.info(full_data['resumo'])
                                else:
                                    st.write("Resumo não disponível")
                            
                            with tab2:
                                if full_data.get('iocs'):
                                    st.write("**🎯 Indicadores de Compromisso Encontrados:**")
                                    
                                    # Organiza IoCs em colunas
                                    ioc_cols = st.columns(2)
                                    col_idx = 0
                                    
                                    for ioc_type, ioc_list in full_data['iocs'].items():
                                        if ioc_list:
                                            with ioc_cols[col_idx % 2]:
                                                st.write(f"**{ioc_type.title()}:** ({len(ioc_list)})")
                                                for ioc in ioc_list[:10]:  # Limita a 10 por tipo
                                                    st.markdown(f"""
                                                    <span class="ioc-tag">{ioc}</span>
                                                    """, unsafe_allow_html=True)
                                                if len(ioc_list) > 10:
                                                    st.caption(f"... e mais {len(ioc_list) - 10} {ioc_type}")
                                            col_idx += 1
                                else:
                                    st.write("Nenhum IoC encontrado")
                            
                            with tab3:
                                if full_data.get('mitre'):
                                    st.write("**⚔️ Técnicas MITRE ATT&CK Identificadas:**")
                                    
                                    # Agrupa por tática
                                    from .utils import get_mitre_technique_name
                                    
                                    for i, technique in enumerate(full_data['mitre'][:15]):  # Limita a 15
                                        # Extrai ID da técnica (pode ser string ou dicionário)
                                        if isinstance(technique, dict):
                                            technique_id = technique.get('id', technique.get('technique_id', 'Unknown'))
                                            technique_name = technique.get('name', technique.get('nome', ''))
                                        else:
                                            technique_id = str(technique)
                                            technique_name = ''
                                        
                                        # Usa função para obter nome se não veio do dicionário
                                        if not technique_name:
                                            tech_name = get_mitre_technique_name(technique_id)
                                        else:
                                            tech_name = technique_name
                                        
                                        st.write(f"**{technique_id}:** {tech_name}")
                                    
                                    if len(full_data['mitre']) > 15:
                                        st.caption(f"... e mais {len(full_data['mitre']) - 15} técnicas")
                                else:
                                    st.write("Nenhuma técnica MITRE identificada")
                            
                            with tab4:
                                st.write("**📥 Ações Disponíveis:**")
                                
                                col_download, col_delete = st.columns(2)
                                
                                with col_download:
                                    # Botão para download
                                    if st.button("📥 Download JSON", key=f"download_{report_id}"):
                                        import json
                                        json_str = json.dumps(full_data, indent=2, ensure_ascii=False)
                                        st.download_button(
                                            label="📁 Baixar Arquivo JSON",
                                            data=json_str,
                                            file_name=f"analise_{report_id}.json",
                                            mime="application/json",
                                            key=f"download_file_{report_id}"
                                        )
                                
                                with col_delete:
                                    # Seção de exclusão
                                    if st.button("🗑️ Excluir Análise", type="secondary", key=f"del_btn_{report_id}"):
                                        st.session_state[f'confirm_del_{report_id}'] = True
                                        st.rerun()
                                
                                # Confirmação de exclusão
                                if st.session_state.get(f'confirm_del_{report_id}', False):
                                    st.warning("⚠️ **Confirmar Exclusão**")
                                    st.write("**Esta ação não pode ser desfeita!**")
                                    
                                    col_confirm, col_cancel = st.columns(2)
                                    
                                    with col_confirm:
                                        if st.button("✅ Sim, Excluir", type="primary", key=f"conf_del_{report_id}"):
                                            with st.spinner("Excluindo..."):
                                                success = self.db.delete_report(report_id)
                                                
                                            if success:
                                                st.success("✅ Análise excluída!")
                                                if f'confirm_del_{report_id}' in st.session_state:
                                                    del st.session_state[f'confirm_del_{report_id}']
                                                st.balloons()
                                                time.sleep(1)
                                                st.rerun()
                                    
                                    with col_cancel:
                                        if st.button("❌ Cancelar", key=f"cancel_del_{report_id}"):
                                            if f'confirm_del_{report_id}' in st.session_state:
                                                del st.session_state[f'confirm_del_{report_id}']
                                            st.rerun()
                        else:
                            st.error("❌ Erro ao carregar dados da análise")
                
                # Ações em lote na parte inferior
                st.divider()
                st.subheader("🔧 Ações em Lote")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("📥 Exportar Relatórios Filtrados", key="export_filtered"):
                        export_data = []
                        for _, report in filtered_reports.iterrows():
                            export_data.append({
                                'ID': report['id'],
                                'Fonte': report['fonte'],
                                'Tipo de Ameaça': report['tipo_ameaca'],
                                'Confiança': report['confianca'],
                                'Data de Análise': report['data_analise']
                            })
                        
                        df_export = pd.DataFrame(export_data)
                        csv_data = df_export.to_csv(index=False, encoding='utf-8')
                        
                        st.download_button(
                            label="📁 Download CSV",
                            data=csv_data,
                            file_name=f"relatorios_filtrados_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv",
                            key="download_filtered_csv"
                        )
                
                with col2:
                    if st.button("⚠️ Excluir Relatórios Filtrados", key="bulk_delete_filtered"):
                        st.session_state['bulk_delete_filtered_mode'] = True
                
                with col3:
                    if st.button("🔄 Limpar Filtros", key="clear_filters"):
                        st.rerun()
                
                # Confirmação para exclusão em lote dos filtrados
                if st.session_state.get('bulk_delete_filtered_mode', False):
                    st.warning("⚠️ **Excluir Relatórios Filtrados**")
                    st.write(f"Tem certeza que deseja excluir **{len(filtered_reports)}** relatório(s) filtrado(s)?")
                    st.write("**Esta ação não pode ser desfeita!**")
                    
                    col_confirm, col_cancel = st.columns(2)
                    
                    with col_confirm:
                        if st.button("✅ Confirmar Exclusão", type="primary", key="bulk_confirm_filtered"):
                            with st.spinner(f"Excluindo {len(filtered_reports)} relatório(s)..."):
                                deleted_count = 0
                                
                                for _, report in filtered_reports.iterrows():
                                    if self.db.delete_report(report['id']):
                                        deleted_count += 1
                                
                                st.session_state['bulk_delete_filtered_mode'] = False
                                st.success(f"✅ {deleted_count} relatório(s) excluído(s)!")
                                st.balloons()
                                time.sleep(1)
                                st.rerun()
                    
                    with col_cancel:
                        if st.button("❌ Cancelar", key="bulk_cancel_filtered"):
                            st.session_state['bulk_delete_filtered_mode'] = False
                            st.rerun()
            
            else:
                st.warning("❌ Nenhum relatório encontrado com os filtros aplicados.")
                st.info("💡 **Sugestões:**")
                st.write("• Remova alguns filtros para ver mais resultados")
                st.write("• Verifique se há análises realizadas")
                st.write("• Use 'Analisar Novo Relatório' para adicionar dados")
        
        else:
            st.info("📂 Nenhum relatório encontrado na base de dados.")
            st.write("Para começar:")
            st.write("• Use 'Analisar Novo Relatório' para fazer upload de arquivos")
            st.write("• Cole texto diretamente")
            st.write("• Analise URLs de relatórios")
    
    def show_individual_statistics(self):
        """
        Página de estatísticas detalhadas por relatório individual
        """
        # st.header("📈 Estatísticas Detalhadas por Relatório")  # Removido para evitar duplicação
        
        # Obtém todos os relatórios
        all_reports = self.db.get_all_reports(limit=1000)
        
        if not all_reports or len(all_reports) == 0:
            st.info("📊 Não há dados suficientes para gerar estatísticas.")
            return
        
        # Seletor de relatório
        report_options = []
        for report in all_reports:
            fonte_display = report['fonte']
            if len(fonte_display) > 50:
                fonte_display = fonte_display[:47] + "..."
            
            option_text = f"ID {report['id']} - {fonte_display} [{report['tipo_ameaca']}]"
            report_options.append(option_text)
        
        selected_option = st.selectbox(
            "📄 Selecione um relatório para ver estatísticas detalhadas:",
            ["Selecione um relatório..."] + report_options
        )
        
        if selected_option != "Selecione um relatório...":
            # Extrai o ID do relatório selecionado
            report_id = int(selected_option.split("ID ")[1].split(" -")[0])
            selected_report = next((r for r in all_reports if r['id'] == report_id), None)
            
            if selected_report:
                # Carrega dados completos
                full_data = self.db._load_full_report(selected_report['json_path'])
                
                if full_data:
                    # Informações básicas
                    st.subheader(f"📊 Estatísticas da Análise - ID {report_id}")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("🎯 Tipo de Ameaça", selected_report['tipo_ameaca'])
                    
                    with col2:
                        st.metric("🎯 Confiança", f"{selected_report['confianca']:.2f}")
                    
                    with col3:
                        total_iocs = sum(len(iocs) for iocs in full_data.get('iocs', {}).values())
                        st.metric("🎯 Total de IoCs", total_iocs)
                    
                    with col4:
                        mitre_count = len(full_data.get('mitre', []))
                        st.metric("⚔️ Técnicas MITRE", mitre_count)
                    
                    # Organiza em tabs
                    tab1, tab2, tab3 = st.tabs(["🎯 Análise de IoCs", "⚔️ Técnicas MITRE", "📊 Resumo Geral"])
                    
                    with tab1:
                        if full_data.get('iocs'):
                            st.subheader("📈 Distribuição de IoCs por Tipo")
                            
                            # Cria dados para gráfico
                            ioc_types = []
                            ioc_counts = []
                            
                            for ioc_type, ioc_list in full_data['iocs'].items():
                                if ioc_list:
                                    ioc_types.append(ioc_type.title())
                                    ioc_counts.append(len(ioc_list))
                            
                            if ioc_types:
                                # Gráfico de barras
                                fig_bar = px.bar(
                                    x=ioc_types,
                                    y=ioc_counts,
                                    title="Quantidade de IoCs por Tipo",
                                    labels={'x': 'Tipo de IoC', 'y': 'Quantidade'},
                                    color=ioc_counts,
                                    color_continuous_scale='Blues'
                                )
                                st.plotly_chart(fig_bar, use_container_width=True)
                                
                                # Gráfico de pizza
                                fig_pie = px.pie(
                                    values=ioc_counts,
                                    names=ioc_types,
                                    title="Distribuição Percentual de IoCs"
                                )
                                st.plotly_chart(fig_pie, use_container_width=True)
                                
                                # Tabela detalhada
                                st.subheader("📋 Detalhes dos IoCs")
                                
                                ioc_data = []
                                for ioc_type, ioc_list in full_data['iocs'].items():
                                    for ioc in ioc_list:
                                        ioc_data.append({
                                            'Tipo': ioc_type.title(),
                                            'Valor': ioc
                                        })
                                
                                if ioc_data:
                                    df_iocs = pd.DataFrame(ioc_data)
                                    st.dataframe(df_iocs, use_container_width=True, hide_index=True)
                        else:
                            st.info("Nenhum IoC encontrado neste relatório")
                    
                    with tab2:
                        if full_data.get('mitre'):
                            st.subheader("⚔️ Análise de Técnicas MITRE ATT&CK")
                            
                            from .utils import get_mitre_technique_name
                            
                            # Prepara dados das técnicas
                            techniques_data = []
                            tactics_count = {}
                            
                            for technique in full_data['mitre']:
                                # Extrai ID da técnica (pode ser string ou dicionário)
                                if isinstance(technique, dict):
                                    technique_id = technique.get('id', technique.get('technique_id', 'Unknown'))
                                    technique_name = technique.get('name', technique.get('nome', ''))
                                else:
                                    technique_id = str(technique)
                                    technique_name = ''
                                
                                # Usa função para obter nome se não veio do dicionário
                                if not technique_name:
                                    tech_name = get_mitre_technique_name(technique_id)
                                else:
                                    tech_name = technique_name
                                
                                # Extrai tática (primeira parte antes do ponto, se existir)
                                if '.' in technique_id:
                                    base_technique = technique_id.split('.')[0]
                                else:
                                    base_technique = technique_id
                                
                                # Mapeia para táticas (simplificado)
                                tactic = self._get_tactic_from_technique(base_technique)
                                
                                techniques_data.append({
                                    'ID': technique_id,
                                    'Nome': tech_name,
                                    'Tática': tactic
                                })
                                
                                tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
                            
                            # Gráfico de táticas
                            if tactics_count:
                                st.subheader("📊 Distribuição por Táticas MITRE")
                                
                                fig_tactics = px.bar(
                                    x=list(tactics_count.keys()),
                                    y=list(tactics_count.values()),
                                    title="Técnicas por Tática MITRE ATT&CK",
                                    labels={'x': 'Tática', 'y': 'Quantidade de Técnicas'},
                                    color=list(tactics_count.values()),
                                    color_continuous_scale='Reds'
                                )
                                fig_tactics.update_xaxes(tickangle=45)
                                st.plotly_chart(fig_tactics, use_container_width=True)
                            
                            # Tabela de técnicas
                            st.subheader("📋 Lista Completa de Técnicas")
                            if techniques_data:
                                df_techniques = pd.DataFrame(techniques_data)
                                st.dataframe(df_techniques, use_container_width=True, hide_index=True)
                        else:
                            st.info("Nenhuma técnica MITRE identificada neste relatório")
                    
                    with tab3:
                        st.subheader("📄 Resumo Geral da Análise")
                        
                        # Informações gerais
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write("**📋 Informações Básicas:**")
                            st.write(f"• **ID do Relatório:** {report_id}")
                            st.write(f"• **Fonte:** {selected_report['fonte']}")
                            st.write(f"• **Data da Análise:** {selected_report['data_analise']}")
                            st.write(f"• **Tipo de Ameaça:** {selected_report['tipo_ameaca']}")
                            st.write(f"• **Nível de Confiança:** {selected_report['confianca']:.2f}")
                        
                        with col2:
                            st.write("**📊 Estatísticas:**")
                            st.write(f"• **Total de IoCs:** {total_iocs}")
                            st.write(f"• **Técnicas MITRE:** {mitre_count}")
                            
                            if full_data.get('iocs'):
                                most_common_ioc = max(full_data['iocs'].items(), key=lambda x: len(x[1]))
                                st.write(f"• **Tipo de IoC Mais Comum:** {most_common_ioc[0].title()} ({len(most_common_ioc[1])} itens)")
                        
                        # Resumo textual
                        if full_data.get('resumo'):
                            st.write("**📝 Resumo da Análise:**")
                            st.info(full_data['resumo'])
                        
                        # Ações disponíveis
                        st.divider()
                        st.subheader("📥 Ações Disponíveis")
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            if st.button("📥 Download JSON Completo", key=f"stats_download_{report_id}"):
                                import json
                                json_str = json.dumps(full_data, indent=2, ensure_ascii=False)
                                st.download_button(
                                    label="📁 Baixar JSON",
                                    data=json_str,
                                    file_name=f"analise_completa_{report_id}.json",
                                    mime="application/json",
                                    key=f"stats_download_file_{report_id}"
                                )
                        
                        with col2:
                            if st.button("📊 Exportar Estatísticas", key=f"export_stats_{report_id}"):
                                # Cria CSV com estatísticas
                                stats_data = {
                                    'Métrica': ['ID', 'Fonte', 'Tipo de Ameaça', 'Confiança', 'Total IoCs', 'Técnicas MITRE', 'Data Análise'],
                                    'Valor': [
                                        report_id,
                                        selected_report['fonte'],
                                        selected_report['tipo_ameaca'], 
                                        f"{selected_report['confianca']:.2f}",
                                        total_iocs,
                                        mitre_count,
                                        selected_report['data_analise']
                                    ]
                                }
                                
                                df_stats = pd.DataFrame(stats_data)
                                csv_data = df_stats.to_csv(index=False, encoding='utf-8')
                                
                                st.download_button(
                                    label="📁 Download CSV",
                                    data=csv_data,
                                    file_name=f"estatisticas_{report_id}.csv",
                                    mime="text/csv",
                                    key=f"stats_csv_{report_id}"
                                )
                        
                        with col3:
                            if st.button("🔍 Ver na Busca", key=f"go_to_search_{report_id}"):
                                st.session_state['selected_report_id'] = report_id
                                st.info("Use o menu lateral para ir para 'Gerenciar e Buscar Relatórios'")
                
                else:
                    st.error("❌ Erro ao carregar dados completos da análise")
        
        # Comparação entre relatórios
        if len(all_reports) > 1:
            st.divider()
            st.subheader("⚖️ Comparação entre Relatórios")
            
            if st.button("📊 Gerar Comparação Geral"):
                # Estatísticas gerais
                df_all = pd.DataFrame(all_reports)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Gráfico de confiança por tipo de ameaça
                    fig_conf = px.box(
                        df_all,
                        x='tipo_ameaca',
                        y='confianca',
                        title="Distribuição de Confiança por Tipo de Ameaça"
                    )
                    fig_conf.update_xaxes(tickangle=45)
                    st.plotly_chart(fig_conf, use_container_width=True)
                
                with col2:
                    # Contagem por tipo de ameaça
                    threat_counts = df_all['tipo_ameaca'].value_counts()
                    fig_threats = px.pie(
                        values=threat_counts.values,
                        names=threat_counts.index,
                        title="Distribuição de Tipos de Ameaça"
                    )
                    st.plotly_chart(fig_threats, use_container_width=True)
    
    def _get_tactic_from_technique(self, technique_id: str) -> str:
        """
        Mapeia técnica MITRE para sua tática principal (simplificado)
        """
        tactic_mapping = {
            'T1566': 'Initial Access',
            'T1204': 'Execution', 
            'T1059': 'Execution',
            'T1053': 'Persistence',
            'T1055': 'Defense Evasion',
            'T1027': 'Defense Evasion',
            'T1082': 'Discovery',
            'T1083': 'Discovery',
            'T1057': 'Discovery',
            'T1087': 'Discovery',
            'T1005': 'Collection',
            'T1041': 'Exfiltration',
            'T1071': 'Command and Control',
            'T1105': 'Command and Control',
        }
        
        return tactic_mapping.get(technique_id, 'Unknown')

    def show_analysis_page(self):
        """
        Página para análise de novos relatórios
        """
        st.header("📄 Analisar Novo Relatório de Segurança")
        
        # Tipo de entrada
        input_type = st.radio(
            "📥 Como deseja fornecer o relatório?",
            ["📝 Texto Direto", "🌐 URL", "📁 Upload de Arquivo"],
            horizontal=True
        )
        
        content = None
        source = None
        
        if input_type == "📝 Texto Direto":
            content = st.text_area(
                "Cole o texto do relatório aqui:",
                height=300,
                placeholder="Cole aqui o conteúdo do relatório de segurança, artigo técnico, ou descrição de incidente..."
            )
            if content:
                source = "texto_direto.txt"
        
        elif input_type == "🌐 URL":
            url = st.text_input(
                "🔗 URL do relatório:",
                placeholder="https://exemplo.com/relatorio-seguranca.html"
            )
            if url and st.button("📥 Baixar Conteúdo"):
                with st.spinner("📥 Baixando conteúdo da URL..."):
                    content = self.collector.collect_from_url(url)
                    if content:
                        source = url
                        st.success("✅ Conteúdo baixado com sucesso!")
                        # Mostra prévia
                        with st.expander("👁️ Prévia do Conteúdo"):
                            st.text(content[:500] + "..." if len(content) > 500 else content)
                    else:
                        st.error("❌ Erro ao baixar conteúdo da URL")
        
        elif input_type == "📁 Upload de Arquivo":
            uploaded_file = st.file_uploader(
                "Selecione um arquivo:",
                type=['pdf', 'txt', 'html', 'htm'],
                help="Formatos suportados: PDF, TXT, HTML"
            )
            
            if uploaded_file:
                # Salva arquivo temporariamente
                temp_path = f"temp_{uploaded_file.name}"
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                # Extrai conteúdo
                with st.spinner("📖 Extraindo conteúdo do arquivo..."):
                    content = self.extractor.extract_from_file(temp_path)
                    if content:
                        source = uploaded_file.name
                        st.success("✅ Arquivo processado com sucesso!")
                        # Remove arquivo temporário
                        Path(temp_path).unlink(missing_ok=True)
                        # Mostra prévia
                        with st.expander("👁️ Prévia do Conteúdo Extraído"):
                            st.text(content[:500] + "..." if len(content) > 500 else content)
                    else:
                        st.error("❌ Erro ao extrair conteúdo do arquivo")
                        Path(temp_path).unlink(missing_ok=True)
        
        # Botão de análise
        if content and source:
            if st.button("🔍 Analisar Relatório", type="primary"):
                with st.spinner("🤖 Analisando relatório com IA..."):
                    # Executa análise
                    analysis = self.nlp.analyze_document(content, source)
                    
                    if analysis:
                        # Salva no banco
                        report_id = self.db.save_analysis(analysis)
                        
                        if report_id:
                            st.success("✅ Análise concluída e salva com sucesso!")
                            
                            # Exibe resultados
                            self.display_analysis_results(analysis)
                        else:
                            st.error("❌ Erro ao salvar análise no banco de dados")
                    else:
                        st.error("❌ Erro durante a análise do documento")

    def show_auto_collection_page(self):
        """
        Página de configuração e controle da coleta automática
        """
        st.header("🤖 Coleta Automática de Relatórios")
        
        # Status do sistema
        stats = self.auto_collector.get_statistics()
        
        # Controles principais
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if not stats["is_running"]:
                if st.button("▶️ Iniciar Coleta Automática", type="primary"):
                    with st.spinner("Iniciando sistema de coleta..."):
                        self.auto_collector.start_scheduler()
                        st.success("✅ Sistema de coleta iniciado!")
                        st.rerun()
            else:
                if st.button("⏹️ Parar Coleta Automática", type="secondary"):
                    with st.spinner("Parando sistema de coleta..."):
                        self.auto_collector.stop_scheduler()
                        st.success("✅ Sistema de coleta parado!")
                        st.rerun()
        
        with col2:
            if st.button("🔄 Executar Coleta Manual"):
                with st.spinner("Executando coleta manual de todas as fontes..."):
                    import asyncio
                    try:
                        # Cria novo loop se necessário
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                        
                        results = loop.run_until_complete(self.auto_collector.collect_all_sources())
                        
                        st.success(f"✅ Coleta concluída! {results['summary']['new_reports']} novos relatórios coletados")
                        
                        with st.expander("📄 Detalhes da Coleta"):
                            st.json(results)
                    
                    except Exception as e:
                        st.error(f"❌ Erro na coleta: {str(e)}")
        
        with col3:
            st.metric("Status", "🟢 Ativo" if stats["is_running"] else "🔴 Inativo")
        
        # Estatísticas do sistema
        st.divider()
        st.subheader("📊 Estatísticas do Sistema")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total de Fontes", stats["total_sources"])
        
        with col2:
            st.metric("Fontes Ativas", stats["enabled_sources"])
        
        with col3:
            st.metric("Coletas Realizadas", stats["stats"]["total_collected"])
        
        with col4:
            st.metric("Última Execução", stats["stats"]["last_run"][:16] if stats["stats"]["last_run"] else "Nunca")
        
        # Gráfico de fontes por categoria
        if stats["sources_by_category"]:
            st.subheader("📈 Distribuição de Fontes por Categoria")
            
            categories_df = pd.DataFrame([
                {"Categoria": k, "Quantidade": v} 
                for k, v in stats["sources_by_category"].items()
            ])
            
            fig = px.pie(
                categories_df,
                values="Quantidade",
                names="Categoria",
                title="Fontes Ativas por Categoria"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Configuração de fontes
        st.divider()
        st.subheader("⚙️ Configuração de Fontes")
        
        sources_status = self.auto_collector.get_sources_status()
        
        # Tabs por categoria
        categories = set(config.get("category", "unknown") for config in sources_status.values())
        tabs = st.tabs([f"📁 {cat.title()}" for cat in sorted(categories)])
        
        for i, category in enumerate(sorted(categories)):
            with tabs[i]:
                st.write(f"**Fontes da categoria: {category.title()}**")
                
                # Filtra fontes desta categoria
                category_sources = {
                    source_id: config for source_id, config in sources_status.items()
                    if config.get("category", "unknown") == category
                }
                
                for source_id, config in category_sources.items():
                    with st.expander(f"🔗 {config['name']}", expanded=False):
                        col1, col2, col3 = st.columns([2, 1, 1])
                        
                        with col1:
                            st.write(f"**URL:** {config['url']}")
                            st.write(f"**Tipo:** {config['type']}")
                            st.write(f"**Frequência:** {config['frequency']}")
                        
                        with col2:
                            current_status = config.get("enabled", True)
                            status_text = "🟢 Ativa" if current_status else "🔴 Inativa"
                            st.write(f"**Status:** {status_text}")
                        
                        with col3:
                            if current_status:
                                if st.button(f"❌ Desativar", key=f"disable_{source_id}"):
                                    self.auto_collector.disable_source(source_id)
                                    st.success(f"Fonte {config['name']} desativada!")
                                    st.rerun()
                            else:
                                if st.button(f"✅ Ativar", key=f"enable_{source_id}"):
                                    self.auto_collector.enable_source(source_id)
                                    st.success(f"Fonte {config['name']} ativada!")
                                    st.rerun()
        
        # Próximas execuções agendadas
        if stats["is_running"] and stats.get("next_scheduled"):
            st.divider()
            st.subheader("⏰ Próximas Execuções Agendadas")
            
            for i, next_run in enumerate(stats["next_scheduled"][:5]):
                st.write(f"**{i+1}.** {next_run}")
        
        # Log de atividades recentes
        st.divider()
        st.subheader("📝 Informações do Sistema")
        
        st.info("""
        **🤖 Sistema de Coleta Automática**
        
        Este sistema coleta automaticamente relatórios de segurança das principais fontes:
        
        **📰 Fontes de Notícias:**
        - Krebs on Security
        - Threatpost  
        - Bleeping Computer
        
        **🏛️ Fontes Governamentais:**
        - CISA Security Alerts
        - US-CERT Alerts
        
        **🔬 Fontes de Pesquisa:**
        - SANS Internet Storm Center
        
        **🔓 Bases de Vulnerabilidades:**
        - MITRE CVE
        - National Vulnerability Database (NVD)
        - CISA Known Exploited Vulnerabilities
        
        **🦠 Fontes de Malware:**
        - Malware Bazaar
        
        O sistema executa coletas em diferentes frequências (horária, diária, semanal) e 
        analisa automaticamente o conteúdo coletado usando IA para extrair IoCs, 
        classificar ameaças e mapear técnicas MITRE ATT&CK.
        """)

    def display_analysis_results(self, analysis: Dict[str, Any]):
        """
        Exibe resultados da análise
        """
        st.subheader("📊 Resultados da Análise")
        
        # Métricas principais
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Tipo de Ameaça", analysis["tipo_ameaca"])
        
        with col2:
            total_iocs = sum(len(iocs) for iocs in analysis["iocs"].values())
            st.metric("IoCs Encontrados", total_iocs)
        
        with col3:
            confidence_pct = analysis["confianca"] * 100
            st.metric("Confiança", f"{confidence_pct:.1f}%")
        
        # Barra de progresso da confiança
        st.progress(analysis["confianca"])
        
        # Resumo
        if analysis.get("resumo"):
            st.subheader("📝 Resumo")
            st.write(analysis["resumo"])
        
        # IoCs
        if analysis.get("iocs"):
            st.subheader("🎯 Indicadores de Compromisso (IoCs)")
            
            for ioc_type, ioc_list in analysis["iocs"].items():
                if ioc_list:
                    st.write(f"**{ioc_type.title()}:**")
                    for ioc in ioc_list:
                        st.markdown(f"""
                        <span class="ioc-tag">{ioc}</span>
                        """, unsafe_allow_html=True)
        
        # Técnicas MITRE
        if analysis.get("mitre"):
            st.subheader("⚔️ Técnicas MITRE ATT&CK")
            
            mitre_df = pd.DataFrame(analysis["mitre"])
            if not mitre_df.empty:
                st.dataframe(mitre_df, use_container_width=True)
        
        # JSON completo
        with st.expander("📄 Ver Análise Completa (JSON)"):
            st.json(analysis)


def main():
    """
    Função principal da aplicação
    """
    interface = ThreatInterface()
    interface.main()

if __name__ == "__main__":
    main() 