=====================================
ATIVIDADE PRÁTICA 1 — HASHING
=====================================
Autores: Leticia Arruda de Freitas e Anthony Gabriel Oliveira Cruz
Disciplina: Segurança em Sistemas Computacionais — IFMT

CONTEÚDO:
  scripts/
    verificador_integridade.py  — Item 2.1
    quebra_sem_salt.py          — Item 2.2
    cadastro_verificacao.py     — Item 2.3
    quebra_com_salt.py          — Item 2.4
    detector_colisao.py         — Parte 4 (Bônus)
    senhas_comuns.txt            — Dicionário de senhas
    hashes_sem_salt.txt          — Hashes alvo (sem salt)
    hashes_com_salt.txt          — Hashes alvo (com salt)
  Relatorio_Tecnico_Hashing.pdf  — Relatório técnico
  Apresentacao_Hashing.pptx      — Apresentação

COMO TESTAR:
  cd scripts/
  mkdir -p dados/subpasta
  echo "teste" > dados/arquivo.txt
  echo "config" > dados/subpasta/config.txt

  python3 verificador_integridade.py dados
  python3 verificador_integridade.py dados --verificar
  python3 quebra_sem_salt.py hashes_sem_salt.txt senhas_comuns.txt
  python3 cadastro_verificacao.py --cadastrar usuario1 minhasenha
  python3 cadastro_verificacao.py --verificar usuario1 minhasenha
  python3 quebra_com_salt.py hashes_com_salt.txt senhas_comuns.txt
  python3 detector_colisao.py
