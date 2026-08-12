window.BENCHMARK_DATA = {
  "lastUpdate": 1786541311110,
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
          "id": "52511f5619f57f06efcdb0f4d1b5d6fa358cf030",
          "message": "Merge pull request #159 from sheeki03/security/b8-product-wiring-artifact-set\n\nB8: wire artifact inspection into scan and package inspect, with artifact-set cross-distribution correlation",
          "timestamp": "2026-08-12T17:23:01+05:30",
          "tree_id": "4986907b986f5376fde20746b7580ab5018782f8",
          "url": "https://github.com/sheeki03/tirith/commit/52511f5619f57f06efcdb0f4d1b5d6fa358cf030"
        },
        "date": 1786535775514,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 249,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 88,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 15029,
            "range": "± 439",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 149858,
            "range": "± 6666",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 127778,
            "range": "± 4495",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 119111,
            "range": "± 4768",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 18915,
            "range": "± 753",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 68,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 80,
            "range": "± 5",
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
          "id": "a0def1cb36f44a2e253b9d9a5f3100971f109ce5",
          "message": "Merge PR #160: DB-B v2 binary format and dual-manifest updater\n\nDB-B: v2 binary format with artifact/file-hash indices, dual-format writer, and dual-manifest updater",
          "timestamp": "2026-08-12T18:00:47+05:30",
          "tree_id": "e878c75b1c79c19dc1eaecc78a6feee4657decf4",
          "url": "https://github.com/sheeki03/tirith/commit/a0def1cb36f44a2e253b9d9a5f3100971f109ce5"
        },
        "date": 1786538031224,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 495,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 136,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 34439,
            "range": "± 1350",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 244902,
            "range": "± 1846",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 211474,
            "range": "± 1745",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 197506,
            "range": "± 675",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24184,
            "range": "± 1069",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 70,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 91,
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
          "id": "bf14ac2404e6712ac24eb08419e7ec14a21f2b0f",
          "message": "Merge PR #161: DB-C staged rollout and cutover gating\n\nDB-C: v2 staged rollout runbook and non-telemetry cutover gating",
          "timestamp": "2026-08-12T18:01:25+05:30",
          "tree_id": "77902699c40d3ff6f19e62667c2f36d48f959db1",
          "url": "https://github.com/sheeki03/tirith/commit/bf14ac2404e6712ac24eb08419e7ec14a21f2b0f"
        },
        "date": 1786538072059,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 476,
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
            "value": 34626,
            "range": "± 314",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 248179,
            "range": "± 4377",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 213608,
            "range": "± 7873",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 199811,
            "range": "± 7539",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24532,
            "range": "± 873",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 88,
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
          "id": "4c83aec02291af6b021409e7fd5cd4d188f8fd1c",
          "message": "Merge PR #162: DB-D publish v2 asset and signed index\n\nDB-D: publish the v2 asset and signed v2 index alongside v1 (Phase-4 cutover)",
          "timestamp": "2026-08-12T18:01:58+05:30",
          "tree_id": "85c4a63166f7e0e3bdb678f09f89248386eb22a9",
          "url": "https://github.com/sheeki03/tirith/commit/4c83aec02291af6b021409e7fd5cd4d188f8fd1c"
        },
        "date": 1786538103257,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 240,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 86,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 14641,
            "range": "± 195",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 144409,
            "range": "± 1785",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 123823,
            "range": "± 3856",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 114929,
            "range": "± 2044",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 18165,
            "range": "± 325",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 56,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 75,
            "range": "± 4",
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
          "id": "9c72dad8f91b0127f09b53456ddb9c17167eadb5",
          "message": "Merge PR #164: package firewall, runtime capsule, and MCP gateway hardening\n\nfeat: package firewall + runtime capsule + MCP gateway hardening (executive-verdict follow-on)",
          "timestamp": "2026-08-12T18:10:53+05:30",
          "tree_id": "b5e574eea5a17f9b48a0671d7b7f41c260cb78c2",
          "url": "https://github.com/sheeki03/tirith/commit/9c72dad8f91b0127f09b53456ddb9c17167eadb5"
        },
        "date": 1786538663774,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 348,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 102,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 30506,
            "range": "± 945",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 188863,
            "range": "± 2769",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 164841,
            "range": "± 7190",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 150637,
            "range": "± 686",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 20068,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 63,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 73,
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
          "id": "e5490709946380aab9bce128d80a103ba838bb55",
          "message": "Merge PR #169: bounded PDF preflight and fail-closed analysis\n\nfix(pdf): preflight nesting-depth guard for lopdf DoS (RUSTSEC-2026-0187)",
          "timestamp": "2026-08-12T18:28:38+05:30",
          "tree_id": "431e8e983a0e9cea7cceb6e8c5f8b8da67da4a17",
          "url": "https://github.com/sheeki03/tirith/commit/e5490709946380aab9bce128d80a103ba838bb55"
        },
        "date": 1786539718683,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 427,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 131,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 39760,
            "range": "± 197",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 248753,
            "range": "± 1084",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 214049,
            "range": "± 1017",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 197466,
            "range": "± 819",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 25983,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 91,
            "range": "± 2",
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
          "id": "e5dfec91f1fa1440d026b60681be3738dae11320",
          "message": "Merge PR #170: sanitize untrusted CLI output with exact approvals\n\nfeat(output): sanitize untrusted fields in human CLI output (terminal control + deceptive Unicode)",
          "timestamp": "2026-08-12T18:45:29+05:30",
          "tree_id": "b9eeb4e937e5c88074dfc965fc93ea1038f610bd",
          "url": "https://github.com/sheeki03/tirith/commit/e5dfec91f1fa1440d026b60681be3738dae11320"
        },
        "date": 1786540719443,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 552,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 132,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 34212,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 245542,
            "range": "± 2443",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 214493,
            "range": "± 1079",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 201371,
            "range": "± 862",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 25604,
            "range": "± 137",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 93,
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
          "id": "99c48b18f45d4fc0dd0573dea492d0f11c4bdeb4",
          "message": "Merge PR #171: structural GitHub Actions security checks\n\nfeat(cifile): structural GitHub Actions security checks",
          "timestamp": "2026-08-12T18:46:03+05:30",
          "tree_id": "720d5c9e885af953beeef494a1a7bc7f82d5e6d4",
          "url": "https://github.com/sheeki03/tirith/commit/99c48b18f45d4fc0dd0573dea492d0f11c4bdeb4"
        },
        "date": 1786540764850,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 482,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 133,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 34080,
            "range": "± 137",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 247242,
            "range": "± 2018",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 215333,
            "range": "± 1189",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 200116,
            "range": "± 827",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 25238,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 68,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 88,
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
          "id": "6809951c286b74268354a5250f1e2ca299d4dd0b",
          "message": "Merge PR #172: command and credential hardening\n\nfeat(command): reverse-shell and suspicious inline-interpreter detection, plus OpenAI/HF/PyPI/PGP credentials",
          "timestamp": "2026-08-12T18:55:09+05:30",
          "tree_id": "dd140cbf284faaabe2b769a25ddb6d49399fef61",
          "url": "https://github.com/sheeki03/tirith/commit/6809951c286b74268354a5250f1e2ca299d4dd0b"
        },
        "date": 1786541310566,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 480,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 139,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 33583,
            "range": "± 930",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 247294,
            "range": "± 1590",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 213095,
            "range": "± 2611",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 198308,
            "range": "± 2724",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 25052,
            "range": "± 90",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 88,
            "range": "± 5",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}