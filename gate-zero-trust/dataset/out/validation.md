# Dataset validation report

Schema `1.2`, generator `1.2.0`. 1665 cases, 1382 malicious, 283 benign.

| # | Check | Result | Detail |
|---|---|---|---|
| 1 | `schema_correctness` | PASS | 1665 rows checked against attack_case.schema.json; 0 violations |
| 2 | `unique_ids` | PASS | 1665 ids, 1665 distinct, 0 duplicated |
| 3 | `id_encoding` | PASS | 1665 ids decoded; 0 inconsistent |
| 4 | `mandatory_fields` | PASS | 28 required fields; 0 missing, 0 null |
| 5 | `category_and_subtype_assignments` | PASS | 120 declared subtypes; 1382 malicious rows; 0 violations |
| 6 | `execution_levels` | PASS | levels present [1, 2, 3]; 0 invalid |
| 7 | `ground_truth_labels` | PASS | 1665 rows; 0 label inconsistencies |
| 8 | `expected_outcomes` | PASS | 1665 rows; 0 outcome inconsistencies |
| 9 | `sequence_consistency` | PASS | 1665 sequences; 0 violations |
| 10 | `benign_and_hard_negatives` | PASS | 283 benign (38 hard negatives) across 16 tools and levels [1, 2, 3] |
| 11 | `class_distributions` | PASS | 11 authored categories, 127 subtypes, every authored category with 10 subtypes |
| 12 | `duplicates` | PASS | 0 copy pairs, 0 near-duplicate description pairs (Jaccard >= 0.9); 4581 cross-level/cross-subtype payload reuses (allowed) |
| 13 | `reproducibility` | PASS | rebuild matches the committed dataset |
| 14 | `manifest_matches_dataset` | PASS | 9 manifest fields compared; 0 drift |

## Distributions

| Category | Cases |
|---|---|
| A | 33 |
| B | 36 |
| C | 72 |
| D | 76 |
| E | 43 |
| F | 49 |
| G | 62 |
| H | 60 |
| I | 60 |
| J | 37 |
| K | 152 |
| X | 985 |

| Level | Malicious | Benign |
|---|---|---|
| 1 | 0 | 0 |
| 2 | 0 | 0 |
| 3 | 0 | 0 |

| Enforcing layer | Malicious cases |
|---|---|
| capability | 186 |
| contracts | 958 |
| dcbf | 42 |
| hitl | 21 |
| ifc | 51 |
| semantic | 78 |
| workflow | 46 |

| Severity | Cases |
|---|---|
| critical | 186 |
| high | 1137 |
| low | 287 |
| medium | 55 |

| Tool | Cases |
|---|---|
| admin_tool | 221 |
| agent_delegate | 36 |
| calendar_api | 7 |
| ci_pipeline | 28 |
| cloud_api | 17 |
| code_execute | 101 |
| data_analysis | 10 |
| database_query | 87 |
| file_read | 37 |
| file_write | 54 |
| format_template | 3 |
| http_request | 141 |
| k8s_api | 22 |
| memory_write | 24 |
| payment_api | 58 |
| send_email | 690 |
| sql_query | 90 |
| web_search | 39 |

## Check evidence

### schema_correctness

```json
{
  "violations": []
}
```

### unique_ids

```json
{
  "duplicates": []
}
```

### id_encoding

```json
{
  "violations": []
}
```

### mandatory_fields

```json
{
  "missing": {},
  "null": []
}
```

### category_and_subtype_assignments

```json
{
  "violations": []
}
```

### execution_levels

```json
{
  "1": 1511,
  "2": 88,
  "3": 66
}
```

### ground_truth_labels

```json
{
  "violations": []
}
```

### expected_outcomes

```json
{
  "violations": []
}
```

### sequence_consistency

```json
{
  "violations": []
}
```

### benign_and_hard_negatives

```json
{
  "by_tool": {
    "agent_delegate": 17,
    "ci_pipeline": 12,
    "cloud_api": 1,
    "code_execute": 9,
    "data_analysis": 2,
    "database_query": 44,
    "file_read": 20,
    "file_write": 33,
    "format_template": 3,
    "http_request": 35,
    "k8s_api": 9,
    "memory_write": 19,
    "payment_api": 22,
    "send_email": 33,
    "sql_query": 8,
    "web_search": 16
  },
  "by_level": {
    "1": 249,
    "2": 28,
    "3": 6
  }
}
```

### class_distributions

```json
{
  "categories_below_10_subtypes": {},
  "imported_subtypes": [
    "X01",
    "X02",
    "X03",
    "X04",
    "X05",
    "X06",
    "X07"
  ]
}
```

### duplicates

```json
{
  "exact": [],
  "near": [],
  "informational_reuse": [
    {
      "a": "ZT-A01-L1-0003",
      "b": "ZT-A01-L3-0001",
      "subtypes": [
        "A01",
        "A01"
      ],
      "levels": [
        1,
        3
      ]
    },
    {
      "a": "ZT-B02-L1-0002",
      "b": "ZT-B02-L2-0001",
      "subtypes": [
        "B02",
        "B02"
      ],
      "levels": [
        1,
        2
      ]
    },
    {
      "a": "ZT-B06-L1-0001",
      "b": "ZT-B06-L2-0001",
      "subtypes": [
        "B06",
        "B06"
      ],
      "levels": [
        1,
        2
      ]
    },
    {
      "a": "ZT-B09-L1-0001",
      "b": "ZT-K02-L3-0002",
      "subtypes": [
        "B09",
        "K02"
      ],
      "levels": [
        1,
        3
      ]
    },
    {
      "a": "ZT-B10-L1-0002",
      "b": "ZT-B10-L2-0001",
      "subtypes": [
        "B10",
        "B10"
      ],
      "levels": [
        1,
        2
      ]
    },
    {
      "a": "ZT-B10-L1-0002",
      "b": "ZT-BEN-L1-0192",
      "subtypes": [
        "B10",
        "B10"
      ],
      "levels": [
        1,
        1
      ]
    },
    {
      "a": "ZT-B10-L2-0001",
      "b": "ZT-BEN-L1-0192",
      "subtypes": [
        "B10",
        "B10"
      ],
      "levels": [
        2,
        1
      ]
    },
    {
      "a": "ZT-BEN-L1-0005",
      "b": "ZT-BEN-L3-0001",
      "subtypes": [
        "D01",
        "K02"
      ],
      "levels": [
        1,
        3
      ]
    },
    {
      "a": "ZT-BEN-L1-0052",
      "b": "ZT-BEN-L3-0005",
      "subtypes": [
        "C04",
        "C02"
      ],
      "levels": [
        1,
        3
      ]
    },
    {
      "a": "ZT-BEN-L1-0153",
      "b": "ZT-BEN-L1-0162",
      "subtypes": [
        "H01",
        "H02"
      ],
      "levels": [
        1,
        1
      ]
    }
  ]
}
```

### reproducibility

```json
{
  "rebuild_sha256": "ad223e5e30a5f4d0176fc634ae2a31019bc523ecbf89687f9c2954a06d5149b7",
  "file_sha256": "ad223e5e30a5f4d0176fc634ae2a31019bc523ecbf89687f9c2954a06d5149b7",
  "manifest_sha256": "ad223e5e30a5f4d0176fc634ae2a31019bc523ecbf89687f9c2954a06d5149b7",
  "rebuild_rows": 1665,
  "file_rows": 1665
}
```

### manifest_matches_dataset

```json
{
  "drift": {}
}
```

## Verdict

All twelve checks pass.
