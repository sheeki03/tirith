window.BENCHMARK_DATA = {
  "lastUpdate": 1786535697382,
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
          "id": "a88c743f8aee8c22336e102dda4d4c244b3ac07b",
          "message": "Merge pull request #154 from sheeki03/security/a4-hardened-wheel-reader\n\nA4: hardened streaming wheel reader with structural-violation rejection",
          "timestamp": "2026-08-12T17:16:36+05:30",
          "tree_id": "77c7bdf254a8b53421b103a69761459dad25f56a",
          "url": "https://github.com/sheeki03/tirith/commit/a88c743f8aee8c22336e102dda4d4c244b3ac07b"
        },
        "date": 1786535355537,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 205,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 66,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 27272,
            "range": "± 1398",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 156631,
            "range": "± 4499",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 134550,
            "range": "± 2464",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 121582,
            "range": "± 1697",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 13779,
            "range": "± 546",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 41,
            "range": "± 1",
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
          "id": "62dc3393eb897986359e01e0588c936ff3b6a052",
          "message": "Merge pull request #155 from sheeki03/security/b5-wheel-installed-record\n\nB5: wheel and installed RECORD integrity with ownership index",
          "timestamp": "2026-08-12T17:17:56+05:30",
          "tree_id": "eccd87821e022e49792cbcf2079420f57bdee101",
          "url": "https://github.com/sheeki03/tirith/commit/62dc3393eb897986359e01e0588c936ff3b6a052"
        },
        "date": 1786535431568,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 204,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 26099,
            "range": "± 246",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 151528,
            "range": "± 2138",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 130839,
            "range": "± 1615",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 126628,
            "range": "± 1936",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 13469,
            "range": "± 125",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 39,
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
          "id": "0df4fbb258252a8c90deebf91318cb3cb0a55ac7",
          "message": "Merge pull request #156 from sheeki03/security/b6-python-startup-execution\n\nB6: Python startup-hook execution analyzer (pth / start / sitecustomize)",
          "timestamp": "2026-08-12T17:20:33+05:30",
          "tree_id": "c60b9c61bffe9bd62480faf50d88fe7046ecb988",
          "url": "https://github.com/sheeki03/tirith/commit/0df4fbb258252a8c90deebf91318cb3cb0a55ac7"
        },
        "date": 1786535632259,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 472,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 134,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 33607,
            "range": "± 811",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 245041,
            "range": "± 5863",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 210073,
            "range": "± 1539",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 198504,
            "range": "± 1060",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 25031,
            "range": "± 148",
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
          "id": "b59213fbb1846ad4f2c70edce14ea3411016f412",
          "message": "Merge pull request #157 from sheeki03/security/b7-native-triage\n\nB7: native binary triage and import-execution-chain correlation",
          "timestamp": "2026-08-12T17:21:45+05:30",
          "tree_id": "7f17b1a6dc649edfc141c98f301cc24f4d91ae4e",
          "url": "https://github.com/sheeki03/tirith/commit/b59213fbb1846ad4f2c70edce14ea3411016f412"
        },
        "date": 1786535696891,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 510,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 134,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 34757,
            "range": "± 485",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 248994,
            "range": "± 2253",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 211645,
            "range": "± 2241",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 201516,
            "range": "± 1296",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24415,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 77,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 93,
            "range": "± 1",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}