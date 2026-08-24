window.BENCHMARK_DATA = {
  "lastUpdate": 1787572847998,
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
          "id": "24a20824f3e0c5b4db3c0393a32409000b7d84b9",
          "message": "feat(threatdb): DigitalSide gated feed source (#173)\n\nfeat(threatdb): DigitalSide gated feed source (defined, CI-disabled pending freshness)",
          "timestamp": "2026-08-12T19:01:13+05:30",
          "tree_id": "277e58e5720b7f70ef5e27a697fead70f3394c0f",
          "url": "https://github.com/sheeki03/tirith/commit/24a20824f3e0c5b4db3c0393a32409000b7d84b9"
        },
        "date": 1786541676052,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 268,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 90,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 16710,
            "range": "± 359",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 166194,
            "range": "± 2365",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 143793,
            "range": "± 2241",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 134877,
            "range": "± 2437",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 21073,
            "range": "± 428",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 64,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 79,
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
          "id": "7db3bed6c5d38b4433e37495da1b0af8010aae33",
          "message": "docs(research): offline-rustsec, web3-phishing, and native-yara spike decisions (#174)\n\ndocs(research): offline-rustsec, web3-phishing, and native-yara spike decision docs",
          "timestamp": "2026-08-12T19:03:53+05:30",
          "tree_id": "2b13a72691218e3ecbd07ae64b06925b0fe99abb",
          "url": "https://github.com/sheeki03/tirith/commit/7db3bed6c5d38b4433e37495da1b0af8010aae33"
        },
        "date": 1786541835219,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 478,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 137,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 34806,
            "range": "± 191",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 248040,
            "range": "± 2395",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 214226,
            "range": "± 2893",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 199369,
            "range": "± 1145",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24769,
            "range": "± 122",
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
            "value": 87,
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
          "id": "13f366f03462f81beead84671a8c7b70b3ec98cf",
          "message": "revert: keep PR #174 research artifacts internal (#192)\n\nrevert: keep PR #174 research artifacts internal",
          "timestamp": "2026-08-12T19:21:54+05:30",
          "tree_id": "277e58e5720b7f70ef5e27a697fead70f3394c0f",
          "url": "https://github.com/sheeki03/tirith/commit/13f366f03462f81beead84671a8c7b70b3ec98cf"
        },
        "date": 1786542896518,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 238,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 80,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 14520,
            "range": "± 454",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 147553,
            "range": "± 7547",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 127143,
            "range": "± 6730",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 115084,
            "range": "± 6667",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 18309,
            "range": "± 1188",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 58,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 70,
            "range": "± 3",
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
          "id": "d5c9bbc27c76a665e99a65c2271be7c91eb8c8dd",
          "message": "fix(security): DeepSec R1 1/5: supervised execution, transactional installs, and signing (#183)\n\nfix(security): DeepSec R1 1/5: supervised execution, transactional installs, and signing",
          "timestamp": "2026-08-12T20:05:38+05:30",
          "tree_id": "c210496b4ff686d9c8cd2801fc2fe40198b7fb02",
          "url": "https://github.com/sheeki03/tirith/commit/d5c9bbc27c76a665e99a65c2271be7c91eb8c8dd"
        },
        "date": 1786545527175,
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
            "value": 132,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 40895,
            "range": "± 808",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 248929,
            "range": "± 1982",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 219774,
            "range": "± 1292",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 198496,
            "range": "± 1633",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 25738,
            "range": "± 72",
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
          "id": "438ea3afc2f36ff5725639ea8802e6aee452db9e",
          "message": "Merge pull request #184 from sheeki03/codex/deepsec-r1b-network-threatdb\n\nfix(security): DeepSec R1 2/5: network, threatdb, resolver, and output boundaries",
          "timestamp": "2026-08-12T21:23:19+05:30",
          "tree_id": "107f8490d4325ecdfc3409c172b787cbacc59b2f",
          "url": "https://github.com/sheeki03/tirith/commit/438ea3afc2f36ff5725639ea8802e6aee452db9e"
        },
        "date": 1786550189821,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 434,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 131,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 40322,
            "range": "± 371",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 242514,
            "range": "± 3642",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 221359,
            "range": "± 3294",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 194749,
            "range": "± 5908",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 25927,
            "range": "± 268",
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
          "id": "168dabbcd4f2b08d75a696e06309a094ae99b782",
          "message": "Merge pull request #185 from sheeki03/codex/deepsec-r1c-setup-provenance\n\nfix(security): DeepSec R1 3/5: setup transactions, install provenance, and script execution",
          "timestamp": "2026-08-12T22:23:31+05:30",
          "tree_id": "6659b8260088ffc420355fe6652be166abfe51ac",
          "url": "https://github.com/sheeki03/tirith/commit/168dabbcd4f2b08d75a696e06309a094ae99b782"
        },
        "date": 1786553910858,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 300,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 105,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 18703,
            "range": "± 340",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 177659,
            "range": "± 2972",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 153315,
            "range": "± 674",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 142910,
            "range": "± 793",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 23503,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 70,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 81,
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
          "id": "35979aaa72fdf19b5421c7e784d8cff4c2ea57e4",
          "message": "Merge pull request #186 from sheeki03/codex/deepsec-r1d-exec-state-core\n\nfix(security): DeepSec R1 4/5: execution state, supervision, and policy core",
          "timestamp": "2026-08-12T23:03:45+05:30",
          "tree_id": "c2ed46b9ea6937f55e1774bc4965cde000814b5c",
          "url": "https://github.com/sheeki03/tirith/commit/35979aaa72fdf19b5421c7e784d8cff4c2ea57e4"
        },
        "date": 1786556251615,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 520,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 127,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 83629,
            "range": "± 1658",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 457864,
            "range": "± 7788",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 593786,
            "range": "± 13572",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 313240,
            "range": "± 2215",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24638,
            "range": "± 334",
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
            "value": 91,
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
          "id": "7a58c55b51e41eb1f5ef50cde75b10cfadd6f24e",
          "message": "Merge pull request #179 from sheeki03/codex/deepsec-r1-critical-boundaries\n\nfix(security): DeepSec R1 5/5: close parser rules, hooks, threatdb, and release boundaries",
          "timestamp": "2026-08-12T23:35:37+05:30",
          "tree_id": "d76069d388f2f5785bc19c42d4336bfaf016e115",
          "url": "https://github.com/sheeki03/tirith/commit/7a58c55b51e41eb1f5ef50cde75b10cfadd6f24e"
        },
        "date": 1786558150054,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 502,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 127,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 82645,
            "range": "± 740",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 446298,
            "range": "± 2807",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 580009,
            "range": "± 4142",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 310806,
            "range": "± 3164",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 24990,
            "range": "± 367",
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
            "value": 92,
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
          "id": "779e7d969b1a2c512b78791a2f3783355a94304b",
          "message": "Merge pull request #187 from sheeki03/codex/deepsec-r2a-core-hardening\n\nfix(security): DeepSec R2 1/2: core hardening queue",
          "timestamp": "2026-08-13T00:36:49+05:30",
          "tree_id": "4ac95a1378666f1d975c82472205791ea8811c7a",
          "url": "https://github.com/sheeki03/tirith/commit/779e7d969b1a2c512b78791a2f3783355a94304b"
        },
        "date": 1786561831289,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 462,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 125,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 93351,
            "range": "± 539",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 426179,
            "range": "± 4334",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 558246,
            "range": "± 10973",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 288855,
            "range": "± 1501",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 32596,
            "range": "± 89",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 80,
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
          "id": "7264d760ddd3e2dfccc5d3a941082cef897491a8",
          "message": "fix(security): DeepSec R2 2/2: CLI, license server, and CI hardening (#180)\n\nfix(security): DeepSec R2 2/2: CLI, license server, and CI hardening",
          "timestamp": "2026-08-13T14:23:20+05:30",
          "tree_id": "3790ec39e8ed43e1e41002a0820af09220f727d1",
          "url": "https://github.com/sheeki03/tirith/commit/7264d760ddd3e2dfccc5d3a941082cef897491a8"
        },
        "date": 1786611432183,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 494,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 123,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 82206,
            "range": "± 415",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 448819,
            "range": "± 9193",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 578349,
            "range": "± 13294",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 305337,
            "range": "± 2748",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 31482,
            "range": "± 369",
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
          "id": "3e7c62d46a724f8a05e0b8cddea7005babd677e5",
          "message": "fix(security): remediate DeepSec R3 reliability and convergence queue (#181)",
          "timestamp": "2026-08-13T16:18:16+05:30",
          "tree_id": "26f51f7a4e42866fbb959860149c2ca1d567458c",
          "url": "https://github.com/sheeki03/tirith/commit/3e7c62d46a724f8a05e0b8cddea7005babd677e5"
        },
        "date": 1786618315635,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 457,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 125,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 91942,
            "range": "± 1725",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 427020,
            "range": "± 5009",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 547912,
            "range": "± 3637",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 291052,
            "range": "± 3346",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 31531,
            "range": "± 124",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 80,
            "range": "± 1",
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
          "id": "6a7ba1d552ded7589791b5276f22868405499ced",
          "message": "merge: consolidate community fixes and agent integrations\n\nLand the verified release stack on main.",
          "timestamp": "2026-08-24T00:58:33+05:30",
          "tree_id": "9f982495493625db627fbb21e504df215d1c789e",
          "url": "https://github.com/sheeki03/tirith/commit/6a7ba1d552ded7589791b5276f22868405499ced"
        },
        "date": 1787513841168,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 453,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 128,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 108723,
            "range": "± 629",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 625193,
            "range": "± 6782",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 879182,
            "range": "± 5356",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 431470,
            "range": "± 7439",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 33551,
            "range": "± 517",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 101,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "web3_clean_command_full_analysis",
            "value": 107533,
            "range": "± 241",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_benign",
            "value": 18995,
            "range": "± 638",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing",
            "value": 31303,
            "range": "± 122",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing_with_cwd",
            "value": 56024,
            "range": "± 239",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing_no_cwd_baseline",
            "value": 17609,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_web3_with_cwd",
            "value": 711287,
            "range": "± 5905",
            "unit": "ns/iter"
          },
          {
            "name": "npm_command_extract",
            "value": 6326,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "task_envelope_decide",
            "value": 1895,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "web3_guard_merge_repo_scoped",
            "value": 3415,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "workflow_artifact_model",
            "value": 20905,
            "range": "± 299",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_hostile_64k",
            "value": 996272,
            "range": "± 12054",
            "unit": "ns/iter"
          },
          {
            "name": "effect_inference_mixed_shell",
            "value": 123724,
            "range": "± 2281",
            "unit": "ns/iter"
          },
          {
            "name": "verdict_json_serialization",
            "value": 640738,
            "range": "± 7716",
            "unit": "ns/iter"
          },
          {
            "name": "task_decision_projection",
            "value": 1317,
            "range": "± 3",
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
          "id": "48748dc9e13a23c618e7cd31f848a199831aee70",
          "message": "Merge pull request #214 from sheeki03/codex/fix-threatdb-update-213\n\nfix(threatdb): restore fresh-client updates and unblock builds",
          "timestamp": "2026-08-24T16:39:53+05:30",
          "tree_id": "ed9ddd08f26eb767e9e6820bf1a2d4117cc18baf",
          "url": "https://github.com/sheeki03/tirith/commit/48748dc9e13a23c618e7cd31f848a199831aee70"
        },
        "date": 1787570217593,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 450,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 132,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 108384,
            "range": "± 1662",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 625228,
            "range": "± 3668",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 885531,
            "range": "± 4444",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 435013,
            "range": "± 6361",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 33310,
            "range": "± 751",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 82,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 101,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "web3_clean_command_full_analysis",
            "value": 108457,
            "range": "± 985",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_benign",
            "value": 19004,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing",
            "value": 31810,
            "range": "± 818",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing_with_cwd",
            "value": 56803,
            "range": "± 122",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing_no_cwd_baseline",
            "value": 17960,
            "range": "± 336",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_web3_with_cwd",
            "value": 720009,
            "range": "± 3152",
            "unit": "ns/iter"
          },
          {
            "name": "npm_command_extract",
            "value": 6400,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "task_envelope_decide",
            "value": 1919,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "web3_guard_merge_repo_scoped",
            "value": 3587,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "workflow_artifact_model",
            "value": 21112,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_hostile_64k",
            "value": 998042,
            "range": "± 31642",
            "unit": "ns/iter"
          },
          {
            "name": "effect_inference_mixed_shell",
            "value": 123054,
            "range": "± 972",
            "unit": "ns/iter"
          },
          {
            "name": "verdict_json_serialization",
            "value": 638366,
            "range": "± 9413",
            "unit": "ns/iter"
          },
          {
            "name": "task_decision_projection",
            "value": 1271,
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
          "id": "f8ec865e11704a3452db8d85fadfdf3588cfa736",
          "message": "Merge pull request #215 from sheeki03/codex/fix-threatdb-ossf-snapshot-cap\n\nfix(threatdb): calibrate pinned OpenSSF snapshot bounds",
          "timestamp": "2026-08-24T17:23:39+05:30",
          "tree_id": "9a71c7c5365670a4720d68452331ecd714eddd4a",
          "url": "https://github.com/sheeki03/tirith/commit/f8ec865e11704a3452db8d85fadfdf3588cfa736"
        },
        "date": 1787572846928,
        "tool": "cargo",
        "benches": [
          {
            "name": "tier1_no_match",
            "value": 458,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "tier1_match",
            "value": 128,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_clean_command",
            "value": 107884,
            "range": "± 5274",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_with_url",
            "value": 628477,
            "range": "± 10670",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_complex_pipeline",
            "value": 877087,
            "range": "± 3959",
            "unit": "ns/iter"
          },
          {
            "name": "paste_analysis",
            "value": 429192,
            "range": "± 13127",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_obfuscated_output",
            "value": 32752,
            "range": "± 793",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_clean",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_ansi",
            "value": 101,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "web3_clean_command_full_analysis",
            "value": 107892,
            "range": "± 403",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_benign",
            "value": 18928,
            "range": "± 324",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing",
            "value": 32339,
            "range": "± 844",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing_with_cwd",
            "value": 56804,
            "range": "± 450",
            "unit": "ns/iter"
          },
          {
            "name": "web3_parse_state_changing_no_cwd_baseline",
            "value": 18388,
            "range": "± 88",
            "unit": "ns/iter"
          },
          {
            "name": "full_analysis_web3_with_cwd",
            "value": 724509,
            "range": "± 12314",
            "unit": "ns/iter"
          },
          {
            "name": "npm_command_extract",
            "value": 6426,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "task_envelope_decide",
            "value": 1945,
            "range": "± 66",
            "unit": "ns/iter"
          },
          {
            "name": "web3_guard_merge_repo_scoped",
            "value": 3513,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "workflow_artifact_model",
            "value": 21437,
            "range": "± 553",
            "unit": "ns/iter"
          },
          {
            "name": "byte_scan_hostile_64k",
            "value": 1016791,
            "range": "± 24725",
            "unit": "ns/iter"
          },
          {
            "name": "effect_inference_mixed_shell",
            "value": 124448,
            "range": "± 879",
            "unit": "ns/iter"
          },
          {
            "name": "verdict_json_serialization",
            "value": 643372,
            "range": "± 16479",
            "unit": "ns/iter"
          },
          {
            "name": "task_decision_projection",
            "value": 1285,
            "range": "± 3",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}