#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["scanpy", "leidenalg", "igraph", "numpy<2"]
# ///
"""A small, real single-cell pipeline: download the pbmc3k dataset from scanpy,
then filter -> normalize -> PCA -> neighbor graph -> Leiden clustering.

It's meant as a workload to *profile* with denet, not a denet API example. The
pipeline has naturally distinct phases (import / download / PCA / neighbors /
cluster), so it's a good showcase for denet's report and regime detection.

Run standalone (uv installs the deps into an ephemeral env):

    uv run scanpy_pbmc.py

Profile it and build a report:

    denet run --json --out scanpy.jsonl uv run scanpy_pbmc.py
    denet-report scanpy.jsonl -o scanpy.html   # needs: pip install denet[report]
"""

import scanpy as sc

sc.settings.verbosity = 1

# 1. download (network) — ~5.9 MB h5ad, cached under ./data after first run
adata = sc.datasets.pbmc3k()

# 2. preprocess (file/CPU) — basic QC filtering, normalization, log transform
sc.pp.filter_cells(adata, min_genes=200)
sc.pp.filter_genes(adata, min_cells=3)
sc.pp.normalize_total(adata, target_sum=1e4)
sc.pp.log1p(adata)
sc.pp.highly_variable_genes(adata, n_top_genes=2000)
adata = adata[:, adata.var.highly_variable].copy()
sc.pp.scale(adata, max_value=10)

# 3. PCA (CPU + memory)
sc.tl.pca(adata, n_comps=50)

# 4. neighbor graph (CPU heavy)
sc.pp.neighbors(adata, n_neighbors=15, n_pcs=40)

# 5. Leiden clustering (CPU)
sc.tl.leiden(adata, flavor="igraph", n_iterations=2, directed=False)

print(f"cells x genes: {adata.n_obs} x {adata.n_vars}")
print("cluster sizes:")
print(adata.obs["leiden"].value_counts().sort_index())
