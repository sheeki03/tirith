window.BENCHMARK_DATA = {
  "lastUpdate": 1786535229513,
  "repoUrl": "https://github.com/sheeki03/tirith",
  "entries": {
    "tirith benchmarks": [
      {
        "commit": {
          "author": {
            "email": "36009418+sheeki03@users.noreply.github.com",
            "name": "Sheeki",
            "username": "sheeki03"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b0ebf00c77928b59b49e21ed29c1746f0c568a54",
          "message": "Merge pull request #150 from sheeki03/security/dba-ossf-parser-confidence\n\nDB-A: parse OpenSSF malicious-package indicators and fix MAL-* confidence (no format change)",
          "timestamp": "2026-08-12T15:25:09+05:30",
          "tree_id": "583687783154b6b96c00c2e364754a630e75666f",
          "url": "https://github.com/sheeki03/tirith/commit/b0ebf00c77928b59b49e21ed29c1746f0c568a54"
        },
        "date": 1786528761950,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 458,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 132,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 34530,
            "range": "± 331",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 246160,
            "range": "± 1705",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 213741,
            "range": "± 2829",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 199624,
            "range": "± 7501",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24610,
            "range": "± 154",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 77,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 96,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "36009418+sheeki03@users.noreply.github.com",
            "name": "Sheeki",
            "username": "sheeki03"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d54ec01f4bb3a96a6ec4c96eb31dd1623f4167c0",
          "message": "Merge pull request #151 from sheeki03/security/a1-package-requirement-model\n\nA1: VersionIntent and constraint-aware package threat assessment",
          "timestamp": "2026-08-12T17:08:29+05:30",
          "tree_id": "e9c585066e052edcdf11010f2e8271e5b7e68ac1",
          "url": "https://github.com/sheeki03/tirith/commit/d54ec01f4bb3a96a6ec4c96eb31dd1623f4167c0"
        },
        "date": 1786534917163,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 445,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 133,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 40594,
            "range": "± 395",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 248840,
            "range": "± 3141",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 218292,
            "range": "± 1474",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 194256,
            "range": "± 1328",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 26385,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 79,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 92,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "36009418+sheeki03@users.noreply.github.com",
            "name": "Sheeki",
            "username": "sheeki03"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "52039e6e91de367d5aee9abbe79f0df1f723fc7b",
          "message": "Merge pull request #152 from sheeki03/security/a2-scan-outcome-coverage-classification\n\nA2: typed scan outcomes, coverage gaps, and file classification",
          "timestamp": "2026-08-12T17:13:58+05:30",
          "tree_id": "422399acb10b9fd3cf9db7aa58b775c93ba83a68",
          "url": "https://github.com/sheeki03/tirith/commit/52039e6e91de367d5aee9abbe79f0df1f723fc7b"
        },
        "date": 1786535227685,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 482,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 135,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 34127,
            "range": "± 1369",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 247333,
            "range": "± 2343",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 216308,
            "range": "± 2385",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 201252,
            "range": "± 1487",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24865,
            "range": "± 340",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 77,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 93,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}