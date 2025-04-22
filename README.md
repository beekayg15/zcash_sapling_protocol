# ZeroCash Sapling Protocol using Arkworks

Implementation of the ZCash sapling protocol using the Arkworks library, in contrast to bellman, used in the OG implmentation. Additional optimizations through recent results in applied cryptography such as circuit-friendly hash functions, etc. are also implemented. Doing so, reduced the number of constraints in the spend/output circuit from ~100K in the OG implementation to ~60K constraints in this implementation.

## Collaborators

- Barath GaneshKumar
- Utkarsh Parkhi
