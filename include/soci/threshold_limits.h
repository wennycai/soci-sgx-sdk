#pragma once

// Public program-structure limit. Batch cardinality must never depend on a
// secret result. 32 covers PRUNE's ratio comparison plus the maximum K=16
// Lagrangian objective comparisons while retaining a small fixed parser bound.
#define SOCI_THRESHOLD_MAX_BATCH_SIZE 32u
