# Dataset validation report

Schema `1.3`, generator `1.3.0`. 1957 cases, 1653 malicious, 304 benign.

| # | Check | Result | Detail |
|---|---|---|---|
| 1 | `schema_correctness` | PASS | 1957 rows checked against attack_case.schema.json; 0 violations |
| 2 | `unique_ids` | PASS | 1957 ids, 1957 distinct, 0 duplicated |
| 3 | `id_encoding` | PASS | 1957 ids decoded; 0 inconsistent |
| 4 | `mandatory_fields` | PASS | 35 required fields; 0 missing, 0 null |
| 5 | `category_and_subtype_assignments` | PASS | 120 declared subtypes; 1653 malicious rows; 0 violations |
| 6 | `execution_levels` | PASS | levels present [1, 2, 3]; 0 invalid |
| 7 | `ground_truth_labels` | PASS | 1957 rows; 0 label inconsistencies |
| 8 | `expected_outcomes` | PASS | 1957 rows; 0 outcome inconsistencies |
| 9 | `sequence_consistency` | PASS | 1957 sequences; 0 violations |
| 10 | `benign_and_hard_negatives` | PASS | 304 benign (50 hard negatives) across 18 tools and levels [1, 2, 3] |
| 11 | `class_distributions` | PASS | 11 authored categories, 127 subtypes, every authored category with 10 subtypes |
| 12 | `duplicates` | PASS | 0 copy pairs, 0 near-duplicate description pairs (Jaccard >= 0.9); 4597 cross-level/cross-subtype payload reuses (allowed) |
| 13 | `reproducibility` | PASS | rebuild matches the committed dataset |
| 14 | `manifest_matches_dataset` | PASS | 11 manifest fields compared; 0 drift |
| 15 | `coverage_requirements` | PASS | 11 authored categories against 20/15/15; 0 below floor |
| 16 | `subcategory_spread` | PASS | max subcategory share 40% per category/complexity and >= 4 distinct subcategories at levels 2-3; 0 concentrated, 0 thin |
| 17 | `record_metadata` | PASS | 1957 records carry consistent complexity, boundary, property, layer and rationale fields; 0 inconsistencies |
| 18 | `attack_benign_separation` | PASS | 972 authored rows; 0 label errors, 0 tools with no benign exercise, 5 shared call shapes (0 without differing context) |

## Distributions

| Category | Cases |
|---|---|
| A | 62 |
| B | 60 |
| C | 91 |
| D | 106 |
| E | 96 |
| F | 77 |
| G | 81 |
| H | 87 |
| I | 84 |
| J | 72 |
| K | 156 |
| X | 985 |

| Level | Malicious | Benign |
|---|---|---|
| 1 | 0 | 0 |
| 2 | 0 | 0 |
| 3 | 0 | 0 |

| Enforcing layer | Malicious cases |
|---|---|
| capability | 242 |
| contracts | 1091 |
| dcbf | 48 |
| hitl | 21 |
| ifc | 76 |
| semantic | 114 |
| workflow | 61 |

| Severity | Cases |
|---|---|
| critical | 309 |
| high | 1264 |
| low | 308 |
| medium | 76 |

| Tool | Cases |
|---|---|
| admin_tool | 241 |
| agent_delegate | 49 |
| calendar_api | 8 |
| ci_pipeline | 40 |
| cloud_api | 22 |
| code_execute | 148 |
| data_analysis | 12 |
| database_query | 102 |
| file_read | 50 |
| file_write | 83 |
| format_template | 3 |
| http_request | 207 |
| k8s_api | 32 |
| memory_write | 25 |
| payment_api | 84 |
| send_email | 712 |
| sql_query | 96 |
| web_search | 43 |

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
  "1": 1517,
  "2": 197,
  "3": 243
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
    "admin_tool": 1,
    "agent_delegate": 17,
    "calendar_api": 1,
    "ci_pipeline": 12,
    "cloud_api": 3,
    "code_execute": 10,
    "data_analysis": 2,
    "database_query": 45,
    "file_read": 21,
    "file_write": 35,
    "format_template": 3,
    "http_request": 37,
    "k8s_api": 12,
    "memory_write": 20,
    "payment_api": 26,
    "send_email": 35,
    "sql_query": 8,
    "web_search": 16
  },
  "by_level": {
    "1": 255,
    "2": 28,
    "3": 21
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
      "a": "ZT-A02-L2-0002",
      "b": "ZT-A02-L3-0003",
      "subtypes": [
        "A02",
        "A02"
      ],
      "levels": [
        2,
        3
      ]
    },
    {
      "a": "ZT-A09-L2-0001",
      "b": "ZT-E07-L3-0002",
      "subtypes": [
        "A09",
        "E07"
      ],
      "levels": [
        2,
        3
      ]
    },
    {
      "a": "ZT-A09-L2-0001",
      "b": "ZT-F07-L2-0001",
      "subtypes": [
        "A09",
        "F07"
      ],
      "levels": [
        2,
        2
      ]
    },
    {
      "a": "ZT-E07-L3-0002",
      "b": "ZT-F07-L2-0001",
      "subtypes": [
        "E07",
        "F07"
      ],
      "levels": [
        3,
        2
      ]
    },
    {
      "a": "ZT-B01-L1-0001",
      "b": "ZT-D01-L3-0002",
      "subtypes": [
        "B01",
        "D01"
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
    }
  ]
}
```

### reproducibility

```json
{
  "rebuild_sha256": "4ed706b94a09a9b8c3d1ec6660e1cab73e26179b9e30488bf89e1153cf7d400f",
  "file_sha256": "4ed706b94a09a9b8c3d1ec6660e1cab73e26179b9e30488bf89e1153cf7d400f",
  "manifest_sha256": "4ed706b94a09a9b8c3d1ec6660e1cab73e26179b9e30488bf89e1153cf7d400f",
  "rebuild_rows": 1957,
  "file_rows": 1957
}
```

### manifest_matches_dataset

```json
{
  "drift": {}
}
```

### coverage_requirements

```json
{
  "below_floor": [],
  "by_category": {
    "A": {
      "atomic": 30,
      "compositional": 15,
      "contextual": 16
    },
    "B": {
      "atomic": 28,
      "compositional": 15,
      "contextual": 15
    },
    "C": {
      "atomic": 30,
      "compositional": 15,
      "contextual": 15
    },
    "D": {
      "atomic": 30,
      "compositional": 15,
      "contextual": 19
    },
    "E": {
      "atomic": 30,
      "compositional": 15,
      "contextual": 38
    },
    "F": {
      "atomic": 29,
      "compositional": 15,
      "contextual": 15
    },
    "G": {
      "atomic": 27,
      "compositional": 15,
      "contextual": 15
    },
    "H": {
      "atomic": 30,
      "compositional": 15,
      "contextual": 15
    },
    "I": {
      "atomic": 29,
      "compositional": 15,
      "contextual": 15
    },
    "J": {
      "atomic": 30,
      "compositional": 15,
      "contextual": 23
    },
    "K": {
      "atomic": 32,
      "compositional": 19,
      "contextual": 36
    }
  }
}
```

### subcategory_spread

```json
{
  "concentrated": [],
  "thin": [],
  "matrix": {
    "A/atomic": {
      "A01": 3,
      "A02": 3,
      "A03": 3,
      "A04": 3,
      "A05": 3,
      "A06": 3,
      "A07": 3,
      "A08": 3,
      "A09": 3,
      "A10": 3
    },
    "A/compositional": {
      "A02": 2,
      "A03": 2,
      "A04": 2,
      "A07": 2,
      "A08": 2,
      "A09": 2,
      "A10": 3
    },
    "A/contextual": {
      "A01": 5,
      "A02": 4,
      "A04": 4,
      "A10": 3
    },
    "B/atomic": {
      "B01": 3,
      "B02": 2,
      "B03": 2,
      "B04": 3,
      "B05": 3,
      "B06": 3,
      "B07": 3,
      "B08": 3,
      "B09": 3,
      "B10": 3
    },
    "B/compositional": {
      "B01": 3,
      "B02": 2,
      "B03": 1,
      "B04": 1,
      "B05": 1,
      "B06": 2,
      "B07": 1,
      "B08": 1,
      "B09": 1,
      "B10": 2
    },
    "B/contextual": {
      "B05": 3,
      "B07": 4,
      "B08": 4,
      "B10": 4
    },
    "C/atomic": {
      "C01": 3,
      "C02": 3,
      "C03": 3,
      "C04": 3,
      "C05": 3,
      "C06": 3,
      "C07": 3,
      "C08": 3,
      "C09": 3,
      "C10": 3
    },
    "C/compositional": {
      "C01": 3,
      "C02": 2,
      "C03": 2,
      "C04": 1,
      "C05": 2,
      "C07": 2,
      "C08": 1,
      "C09": 1,
      "C10": 1
    },
    "C/contextual": {
      "C01": 4,
      "C03": 4,
      "C07": 1,
      "C09": 3,
      "C10": 3
    },
    "D/atomic": {
      "D01": 3,
      "D02": 3,
      "D03": 3,
      "D04": 3,
      "D05": 3,
      "D06": 3,
      "D07": 3,
      "D08": 3,
      "D09": 3,
      "D10": 3
    },
    "D/compositional": {
      "D01": 3,
      "D02": 3,
      "D03": 1,
      "D05": 2,
      "D06": 2,
      "D07": 1,
      "D08": 1,
      "D09": 1,
      "D10": 1
    },
    "D/contextual": {
      "D01": 5,
      "D02": 4,
      "D03": 2,
      "D05": 2,
      "D08": 6
    },
    "E/atomic": {
      "E01": 3,
      "E02": 3,
      "E03": 3,
      "E04": 3,
      "E05": 3,
      "E06": 3,
      "E07": 3,
      "E08": 3,
      "E09": 3,
      "E10": 3
    },
    "E/compositional": {
      "E01": 2,
      "E02": 1,
      "E03": 1,
      "E04": 2,
      "E05": 1,
      "E06": 1,
      "E07": 2,
      "E08": 3,
      "E09": 1,
      "E10": 1
    },
    "E/contextual": {
      "E01": 6,
      "E05": 6,
      "E07": 15,
      "E08": 6,
      "E10": 5
    },
    "F/atomic": {
      "F01": 3,
      "F02": 3,
      "F03": 3,
      "F04": 3,
      "F05": 3,
      "F06": 3,
      "F07": 3,
      "F08": 3,
      "F09": 2,
      "F10": 3
    },
    "F/compositional": {
      "F01": 2,
      "F02": 2,
      "F03": 2,
      "F04": 3,
      "F05": 1,
      "F06": 1,
      "F07": 1,
      "F08": 2,
      "F09": 1
    },
    "F/contextual": {
      "F02": 5,
      "F05": 4,
      "F07": 3,
      "F08": 3
    },
    "G/atomic": {
      "G01": 3,
      "G02": 2,
      "G03": 3,
      "G04": 2,
      "G05": 3,
      "G06": 3,
      "G07": 2,
      "G08": 3,
      "G09": 3,
      "G10": 3
    },
    "G/co
```

### record_metadata

```json
{
  "violations": []
}
```

### attack_benign_separation

```json
{
  "label_errors": [],
  "unexercised_tools": [],
  "shared_call_shapes": 5,
  "indistinguishable": []
}
```

## Verdict

All 18 checks pass.

Coverage matrix: `coverage.md`, `coverage.csv`, `coverage.json`.
