#!/usr/bin/env python3
"""
Item 2.1 - Verificador de Integridade de Arquivo
Autores: Leticia Arruda de Freitas e Anthony Gabriel Oliveira Cruz
Disciplina: Segurança em Sistemas Computacionais - IFMT

Este script calcula hashes SHA-256 de todos os arquivos em um diretório
(recursivamente) e permite verificar se houve alterações posteriores.

Uso:
    python verificador_integridade.py <diretorio>              # Gera hashes.txt
    python verificador_integridade.py <diretorio> --verificar  # Verifica integridade
"""

import hashlib
import os
import sys

# Tamanho do bloco para leitura em chunks (8 KB)
# Garante que arquivos grandes (> 1 GB) não estourem a memória RAM
TAMANHO_BLOCO = 8192


def calcular_hash_sha256(caminho_arquivo):
    """
    Calcula o hash SHA-256 de um arquivo usando leitura em blocos (chunks).

    A leitura em blocos é essencial para processar arquivos grandes sem
    consumir memória excessiva. O hashlib.sha256() mantém um estado interno
    que é atualizado incrementalmente com cada bloco lido.

    Args:
        caminho_arquivo: Caminho completo do arquivo a ser hasheado.

    Returns:
        String hexadecimal do hash SHA-256 do arquivo.
    """
    sha256 = hashlib.sha256()

    # Abre o arquivo em modo binário para garantir leitura correta
    # independente do sistema operacional e encoding do arquivo
    with open(caminho_arquivo, 'rb') as f:
        while True:
            bloco = f.read(TAMANHO_BLOCO)
            if not bloco:
                break
            sha256.update(bloco)

    return sha256.hexdigest()


def listar_arquivos_recursivamente(diretorio):
    """
    Percorre recursivamente o diretório e retorna todos os caminhos de arquivos.

    Utiliza os.walk() para varrer subpastas. Os caminhos são normalizados
    com os.path.normpath() para consistência entre execuções.

    Args:
        diretorio: Caminho do diretório raiz a ser varrido.

    Returns:
        Lista ordenada de caminhos relativos dos arquivos encontrados.
    """
    arquivos = []
    for raiz, _, nomes_arquivos in os.walk(diretorio):
        for nome in nomes_arquivos:
            caminho_completo = os.path.join(raiz, nome)
            # Normaliza o caminho para evitar inconsistências (ex: ./dados vs dados)
            caminho_normalizado = os.path.normpath(caminho_completo)
            arquivos.append(caminho_normalizado)

    # Ordena para garantir saída determinística
    arquivos.sort()
    return arquivos


def gerar_hashes(diretorio, arquivo_saida="hashes.txt"):
    """
    Modo de geração: calcula SHA-256 de cada arquivo e salva em hashes.txt.

    O formato de saída segue o padrão exigido: caminho_do_arquivo:hash
    Cada linha contém o caminho relativo do arquivo seguido de ':' e o hash.

    Args:
        diretorio: Diretório a ser varrido.
        arquivo_saida: Nome do arquivo de saída (padrão: hashes.txt).
    """
    arquivos = listar_arquivos_recursivamente(diretorio)

    if not arquivos:
        print(f"[AVISO] Nenhum arquivo encontrado em '{diretorio}'.")
        return

    print(f"[INFO] Calculando hashes de {len(arquivos)} arquivo(s)...")

    with open(arquivo_saida, 'w', encoding='utf-8') as f_saida:
        for caminho in arquivos:
            try:
                hash_hex = calcular_hash_sha256(caminho)
                linha = f"{caminho}:{hash_hex}"
                f_saida.write(linha + '\n')
                print(f"  [OK] {caminho}")
            except PermissionError:
                print(f"  [ERRO] Sem permissão para ler: {caminho}")
            except Exception as e:
                print(f"  [ERRO] Falha ao processar {caminho}: {e}")

    print(f"\n[SUCESSO] Hashes salvos em '{arquivo_saida}'.")


def carregar_hashes(arquivo_hashes="hashes.txt"):
    """
    Carrega os hashes previamente registrados do arquivo hashes.txt.

    Faz o parse de cada linha no formato caminho:hash, construindo
    um dicionário para busca eficiente durante a verificação.

    Args:
        arquivo_hashes: Caminho do arquivo de hashes.

    Returns:
        Dicionário {caminho_arquivo: hash_sha256}.
    """
    hashes = {}

    with open(arquivo_hashes, 'r', encoding='utf-8') as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            # Usa rsplit com maxsplit=1 para lidar com ':' no caminho do arquivo
            partes = linha.rsplit(':', 1)
            if len(partes) == 2:
                caminho, hash_hex = partes
                hashes[caminho] = hash_hex

    return hashes


def verificar_integridade(diretorio, arquivo_hashes="hashes.txt"):
    """
    Modo de verificação: compara o estado atual com os hashes registrados.

    Classifica cada arquivo em uma das quatro categorias:
    - Inalterado: hash atual == hash registrado
    - Modificado: hash atual != hash registrado (possível adulteração)
    - Novo: arquivo existe mas não consta no registro
    - Removido: arquivo consta no registro mas não existe mais

    Args:
        diretorio: Diretório a ser verificado.
        arquivo_hashes: Arquivo com os hashes de referência.
    """
    if not os.path.exists(arquivo_hashes):
        print(f"[ERRO] Arquivo '{arquivo_hashes}' não encontrado.")
        print("       Execute primeiro sem --verificar para gerar os hashes.")
        sys.exit(1)

    # Carrega hashes de referência
    hashes_registrados = carregar_hashes(arquivo_hashes)

    # Calcula hashes atuais
    arquivos_atuais = listar_arquivos_recursivamente(diretorio)
    hashes_atuais = {}
    for caminho in arquivos_atuais:
        try:
            hashes_atuais[caminho] = calcular_hash_sha256(caminho)
        except Exception as e:
            print(f"  [ERRO] Falha ao processar {caminho}: {e}")

    # Classificação dos arquivos
    inalterados = []
    modificados = []
    novos = []
    removidos = []

    # Verifica arquivos atuais contra o registro
    for caminho, hash_atual in hashes_atuais.items():
        if caminho in hashes_registrados:
            if hash_atual == hashes_registrados[caminho]:
                inalterados.append(caminho)
            else:
                modificados.append(caminho)
        else:
            novos.append(caminho)

    # Verifica arquivos que estavam no registro mas foram removidos
    for caminho in hashes_registrados:
        if caminho not in hashes_atuais:
            removidos.append(caminho)

    # Exibe o relatório de integridade
    print("=" * 60)
    print("       RELATÓRIO DE VERIFICAÇÃO DE INTEGRIDADE")
    print("=" * 60)

    print(f"\n[ARQUIVOS INALTERADOS] ({len(inalterados)})")
    for arq in inalterados:
        print(f"  ✔ {arq}")

    print(f"\n[ARQUIVOS MODIFICADOS] ({len(modificados)})")
    for arq in modificados:
        print(f"  ⚠ {arq}")
        print(f"    Registrado: {hashes_registrados[arq]}")
        print(f"    Atual:      {hashes_atuais[arq]}")

    print(f"\n[ARQUIVOS NOVOS] ({len(novos)})")
    for arq in novos:
        print(f"  + {arq}")

    print(f"\n[ARQUIVOS REMOVIDOS] ({len(removidos)})")
    for arq in removidos:
        print(f"  - {arq}")

    print("\n" + "=" * 60)
    total = len(inalterados) + len(modificados) + len(novos) + len(removidos)
    print(f"Total analisado: {total} arquivo(s)")
    print(f"  Inalterados: {len(inalterados)} | Modificados: {len(modificados)}")
    print(f"  Novos: {len(novos)} | Removidos: {len(removidos)}")
    print("=" * 60)


def main():
    """Ponto de entrada principal do script."""
    if len(sys.argv) < 2:
        print("Uso: python verificador_integridade.py <diretorio> [--verificar]")
        print("  <diretorio>    Caminho do diretório a ser analisado")
        print("  --verificar    Compara estado atual com hashes registrados")
        sys.exit(1)

    diretorio = sys.argv[1]

    if not os.path.isdir(diretorio):
        print(f"[ERRO] '{diretorio}' não é um diretório válido.")
        sys.exit(1)

    modo_verificar = '--verificar' in sys.argv

    if modo_verificar:
        print("[MODO] Verificação de integridade")
        verificar_integridade(diretorio)
    else:
        print("[MODO] Geração de hashes")
        gerar_hashes(diretorio)


if __name__ == '__main__':
    main()
