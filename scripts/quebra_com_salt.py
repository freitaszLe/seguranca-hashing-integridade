#!/usr/bin/env python3
"""
Item 2.4 - Ataque de Dicionário com Salt (Força Bruta Inteligente)
Autores: Leticia Arruda de Freitas e Anthony Gabriel Oliveira Cruz
Disciplina: Segurança em Sistemas Computacionais - IFMT

Este script realiza um ataque de dicionário contra hashes SHA-256 COM salt.
Demonstra como o salt impacta significativamente o custo computacional do ataque.

Inclui otimização de pré-computação: salts reutilizados são processados
uma única vez (desafio bônus).

Uso:
    python quebra_com_salt.py hashes_com_salt.txt senhas_comuns.txt
"""

import hashlib
import sys
import time


def carregar_arquivo_linhas(caminho):
    """
    Carrega um arquivo texto e retorna lista de linhas limpas.

    Args:
        caminho: Caminho do arquivo.

    Returns:
        Lista de strings.
    """
    linhas = []
    with open(caminho, 'r', encoding='utf-8') as f:
        for linha in f:
            linha_limpa = linha.strip()
            if linha_limpa:
                linhas.append(linha_limpa)
    return linhas


def calcular_hash_com_salt(salt_bytes, senha):
    """
    Calcula SHA-256(salt + senha).

    Args:
        salt_bytes: Salt em bytes.
        senha: Senha em texto (string).

    Returns:
        Hash SHA-256 em hexadecimal.
    """
    dados = salt_bytes + senha.encode('utf-8')
    return hashlib.sha256(dados).hexdigest()


def quebrar_hashes_com_salt(arquivo_hashes, arquivo_senhas):
    """
    Executa ataque de dicionário contra hashes com salt.

    Implementa a otimização de pré-computação por salt (desafio bônus):
    - Agrupa os hashes por salt
    - Para cada salt único, calcula o hash de cada senha do dicionário uma vez
    - Verifica todos os hashes daquele salt contra a tabela pré-computada

    Sem otimização: O(hashes * senhas) cálculos de hash
    Com otimização: O(salts_únicos * senhas) cálculos de hash

    Quando salts são reutilizados, a economia é significativa.

    Args:
        arquivo_hashes: Arquivo com linhas no formato salt_hex:hash_hex.
        arquivo_senhas: Dicionário de senhas comuns.
    """
    # Carrega dados
    linhas_hashes = carregar_arquivo_linhas(arquivo_hashes)
    senhas = carregar_arquivo_linhas(arquivo_senhas)

    # Parse das entradas: extrai salt e hash de cada linha
    entradas = []
    for linha in linhas_hashes:
        partes = linha.split(':')
        if len(partes) == 2:
            salt_hex, hash_hex = partes
            entradas.append((salt_hex, hash_hex.lower()))

    print(f"[INFO] {len(entradas)} hash(es) com salt carregado(s)")
    print(f"[INFO] {len(senhas)} senha(s) no dicionário")

    # ---- OTIMIZAÇÃO BÔNUS: Agrupamento por salt ----
    # Agrupa entradas pelo salt para evitar recomputação
    salt_para_hashes = {}
    for salt_hex, hash_hex in entradas:
        if salt_hex not in salt_para_hashes:
            salt_para_hashes[salt_hex] = []
        salt_para_hashes[salt_hex].append(hash_hex)

    salts_unicos = len(salt_para_hashes)
    salts_reutilizados = sum(1 for v in salt_para_hashes.values() if len(v) > 1)
    print(f"[INFO] {salts_unicos} salt(s) único(s) encontrado(s)")
    if salts_reutilizados > 0:
        print(f"[OTIMIZAÇÃO] {salts_reutilizados} salt(s) reutilizado(s) — "
              f"economia de {len(entradas) - salts_unicos} ciclos completos de dicionário")
    print("-" * 70)

    inicio = time.time()

    # Dicionário de resultados: (salt_hex, hash_hex) -> senha ou None
    resultados = {}

    # Para cada salt único, pré-computa os hashes de todas as senhas
    for salt_hex, lista_hashes in salt_para_hashes.items():
        salt_bytes = bytes.fromhex(salt_hex)

        # Converte lista de hashes alvo em um set para busca O(1)
        hashes_alvo = set(lista_hashes)
        hashes_encontrados = set()

        # Testa cada senha do dicionário contra este salt
        for senha in senhas:
            hash_calculado = calcular_hash_com_salt(salt_bytes, senha)

            if hash_calculado in hashes_alvo:
                # Senha encontrada — registra para todos os hashes que usam este salt
                for h in lista_hashes:
                    if h == hash_calculado:
                        resultados[(salt_hex, h)] = senha
                        hashes_encontrados.add(h)

            # Se todos os hashes deste salt foram quebrados, pula para o próximo
            if hashes_encontrados == hashes_alvo:
                break

    tempo_total = time.time() - inicio

    # Exibe resultados na ordem original
    encontradas = 0
    for salt_hex, hash_hex in entradas:
        chave = (salt_hex, hash_hex)
        if chave in resultados:
            print(f"{salt_hex}:{hash_hex} -> {resultados[chave]}")
            encontradas += 1
        else:
            print(f"{salt_hex}:{hash_hex} -> NAO_ENCONTRADA")

    # Estatísticas
    print("-" * 70)
    print(f"[RESULTADO] {encontradas}/{len(entradas)} senha(s) quebrada(s)")
    print(f"[TEMPO] Total: {tempo_total:.4f}s")
    if len(entradas) > 0:
        print(f"[TEMPO] Média por hash: {tempo_total/len(entradas):.6f}s")
    print(f"[INFO] Cálculos de hash realizados: ~{salts_unicos * len(senhas)}")
    print(f"[INFO] Sem otimização seriam: ~{len(entradas) * len(senhas)}")


def main():
    """Ponto de entrada principal."""
    if len(sys.argv) != 3:
        print("Uso: python quebra_com_salt.py <hashes_com_salt.txt> <senhas_comuns.txt>")
        sys.exit(1)

    quebrar_hashes_com_salt(sys.argv[1], sys.argv[2])


if __name__ == '__main__':
    main()
