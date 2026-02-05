# 📘 Organização de Logs OpenSSH para Identificação de Ataques

## 1. Visão Geral

Este projeto implementa um protótipo em Python para análise e
organização de logs do OpenSSH, com o objetivo de identificar possíveis
tentativas de ataque por meio da combinação de heurísticas clássicas e
um agente de Inteligência Artificial não supervisionado.

## 3. Arquitetura da Solução

Fluxo geral do sistema:

Logs OpenSSH → Pré-processamento → Estruturação → Heurísticas → Agente
de IA → Resumo de Segurança

## 4. Funcionalidades Implementadas

-   Leitura de logs OpenSSH
-   Remoção de informações irrelevantes com Regex
-   Normalização e tokenização
-   Estruturação dos eventos
-   Detecção heurística de ataques
-   Detecção de anomalias com IA
-   Geração de resumo interpretável

## 5. Heurísticas de Detecção

-   Força bruta (múltiplas falhas por IP)
-   Enumeração de usuários
-   Login suspeito após falhas

## 6. Uso de Inteligência Artificial

O sistema utiliza aprendizado de máquina não supervisionado: -
Vetorização dos logs com TF-IDF - Agrupamento com DBSCAN - Eventos
anômalos são identificados automaticamente

## 7. Como Executar

Requisitos: - Python 3.8+ - scikit-learn

Instalação: pip install scikit-learn

Execução: python main.py

## 8. Limitações

-   Limiares fixos nas heurísticas
-   Custo computacional do DBSCAN
-   Ausência de correlação temporal avançada
