# Dados compactados

Cópia, em `.gz`, dos dados que **não podem ser recriados com certeza** (o NVD muda com o tempo) ou que são
pesados demais para guardar descompactados no Git. Cada arquivo é a versão original, só comprimida.

```
dados_compactados/
  projeto/data/
    nvd-2024-raw/*.json.gz              as 23 páginas da API do NVD de 2024 (Fase A)
    nvd-2024-filtered.jsonl.gz          corpus filtrado da replicação
    nvd-2024-filtered-variant.jsonl.gz  corpus da variante (usado pela extensão)
  extensao/data/raw/nvd-2025/*.json.gz  as 23 páginas da API do NVD de 2025 (Fase D)
```

## Para usar

Na raiz do repositório:

```
python verificar.py --preparar-dados
```

Isso descompacta cada arquivo no lugar certo (por exemplo, `projeto/data/nvd-2024-filtered.jsonl`) e confere o
**SHA-256** contra os manifestos de `extensao/freeze/` e `extensao/data/raw/nvd-2025/manifest.json`. Se algum
arquivo não bater, o script avisa e não o instala.

Os arquivos descompactados são ignorados pelo Git (ver `.gitignore`), então não aparecem como alteração.
