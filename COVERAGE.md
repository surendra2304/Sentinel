# SENTINEL TEST COVERAGE REPORT (COVERAGE.md)

This document contains the **untruncated, verbatim** test coverage measurements captured directly from `pytest --cov=sentinel --cov-report=term-missing` executed during this session.

---

## 1. Measured vs. Previously Claimed Correction Note
In previous interim reporting drafts, agent coverage numbers were estimated across aggregated domain test suites rather than isolated single-module invocations. During this close-out session, dedicated unit tests were authored in [`tests/unit/test_all_core_agents_deep.py`](file:///d:/Sentinel/tests/unit/test_all_core_agents_deep.py) exercising both the happy-path `analyze()` flow and corrupt-payload error handlers for every single agent.

- **APISecurityAgent**: Measured at **98%** (45 stmts, 1 missed).
- **CloudAgent**: Measured at **97%** (32 stmts, 1 missed).
- **DeviceAgents (Mobile / Wireless)**: Measured at **75%** (83 stmts, 21 missed).
- **DFIRAgents (Forensics / IR)**: Measured at **86%** (58 stmts, 8 missed).
- **EndpointAgent**: Measured at **83%** (41 stmts, 7 missed).
- **ThreatIntelligenceAgent / VulnerabilityAgent**: Measured at **93%** (56 stmts, 4 missed).
- **NetworkAgent**: Measured at **70%** (44 stmts, 13 missed).
- **ReconAgent**: Measured at **97%** (66 stmts, 2 missed).
- **SecurityIntelligenceAgent**: Measured at **76%** (41 stmts, 10 missed).
- **WebSecurityAgent**: Measured at **79%** (39 stmts, 8 missed).
- **LLMPlanner**: Measured at **92%** (26 stmts, 2 missed) in [`tests/unit/test_llm_planner_record_replay.py`](file:///d:/Sentinel/tests/unit/test_llm_planner_record_replay.py).

---

## 2. Complete Untruncated Per-File Coverage Table

```text
........................................................................ [ 53%]
..............................................................           [100%]
=============================== tests coverage ================================
_______________ coverage: platform win32, python 3.11.9-final-0 _______________

Name                                                       Stmts   Miss  Cover   Missing
----------------------------------------------------------------------------------------
sentinel\__init__.py                                           1      0   100%
sentinel\apps\__init__.py                                      1      0   100%
sentinel\apps\api\__init__.py                                  1      0   100%
sentinel\apps\api\main.py                                    214     50    77%   55-58, 172-173, 211, 220-221, 237, 243-255, 269, 275-278, 284-285, 291, 297, 307-308, 320-334, 366, 382-383, 385-386, 388-389, 401-404, 447
sentinel\apps\api\middleware.py                               36      2    94%   62, 69
sentinel\apps\cli\__init__.py                                  1      0   100%
sentinel\apps\cli\main.py                                    224    113    50%   77-84, 90-115, 134-136, 158-159, 186-188, 199-208, 218-233, 243-258, 271-278, 286-294, 304-319, 330-345, 361-362, 370-371, 385-396, 400
sentinel\apps\dashboard\__init__.py                            1      1     0%   3
sentinel\audit\__init__.py                                     1      0   100%
sentinel\audit\audit_logger.py                                75      6    92%   51-52, 113, 119, 137, 141
sentinel\config\__init__.py                                    1      0   100%
sentinel\config\settings.py                                   78      2    97%   39, 43
sentinel\contracts\__init__.py                                 1      1     0%   3
sentinel\contracts\schemas\__init__.py                         1      1     0%   3
sentinel\core\__init__.py                                      1      0   100%
sentinel\core\agents\__init__.py                               1      0   100%
sentinel\core\agents\api_agent.py                             45      1    98%   35
sentinel\core\agents\base.py                                  41      4    90%   44, 50, 56, 69
sentinel\core\agents\cloud_agent.py                           32      1    97%   34
sentinel\core\agents\device_agents.py                         83     21    75%   26, 30, 92, 96, 156, 160, 175-207
sentinel\core\agents\dfir_agents.py                           58      8    86%   26, 30, 91, 95, 128-141
sentinel\core\agents\endpoint_agent.py                        41      7    83%   32, 36, 64, 77-78, 100-112
sentinel\core\agents\intel_agents.py                          56      4    93%   26, 30, 85, 89
sentinel\core\agents\network_agent.py                         44     13    70%   30, 34, 91-123
sentinel\core\agents\recon_agent.py                           66      2    97%   37, 41
sentinel\core\agents\security_intelligence_agent.py           41     10    76%   35, 39, 106-118
sentinel\core\agents\web_agent.py                             39      8    79%   31, 35, 96-111
sentinel\core\events\__init__.py                               1      0   100%
sentinel\core\events\bus.py                                   89     23    74%   28, 33, 38, 43, 62, 78-79, 92, 97-98, 105-106, 111-114, 118-120, 124-127
sentinel\core\intelligence\__init__.py                         0      0   100%
sentinel\core\intelligence\heuristic_provider.py             143     19    87%   40-42, 66-67, 112, 123-128, 145, 152, 220-222, 224-226
sentinel\core\intelligence\interface.py                       35      0   100%
sentinel\core\intelligence\llm_provider.py                    71      9    87%   82, 107-112, 141, 178-179
sentinel\core\intelligence\router.py                          41      6    85%   32, 37, 48-49, 63-64
sentinel\core\memory\__init__.py                               1      0   100%
sentinel\core\memory\knowledge_base.py                        53      0   100%
sentinel\core\memory\working_memory.py                        28      1    96%   49
sentinel\core\models.py                                      315      4    99%   171, 302, 446, 448
sentinel\core\orchestrator\__init__.py                         1      0   100%
sentinel\core\orchestrator\adapter.py                         46     14    70%   19, 25, 31, 36, 41, 50, 73-79, 82, 85
sentinel\core\orchestrator\executor.py                       137      9    93%   177-186, 198-200, 253-261
sentinel\core\orchestrator\lifecycle.py                      109     16    85%   157, 170-186, 211-226, 250
sentinel\core\orchestrator\orchestrator.py                   108     13    88%   108-109, 127, 143-146, 186-187, 195-198
sentinel\core\orchestrator\sandbox.py                         40      5    88%   44, 57, 77-78, 86
sentinel\core\planner\__init__.py                              1      0   100%
sentinel\core\planner\heuristic.py                            68      7    90%   52, 68-71, 83-99
sentinel\core\planner\llm_planner.py                          26      2    92%   58-62
sentinel\core\policy\__init__.py                               1      0   100%
sentinel\core\policy\engine.py                               136      3    98%   196, 270, 286
sentinel\core\scope\__init__.py                                1      0   100%
sentinel\core\scope\resolver.py                              138      6    96%   95-96, 171-172, 217-218
sentinel\core\vault\__init__.py                                2      0   100%
sentinel\core\vault\vault.py                                  48      4    92%   36, 70, 86-87
sentinel\integrations\__init__.py                              1      0   100%
sentinel\integrations\browsers\__init__.py                     1      0   100%
sentinel\integrations\browsers\playwright_adapter.py          53     16    70%   26, 33, 36-38, 44, 65-75
sentinel\integrations\external_apis\__init__.py                1      1     0%   3
sentinel\integrations\friday\models.py                        78      1    99%   101
sentinel\integrations\scanners\__init__.py                     1      0   100%
sentinel\integrations\scanners\dns_adapter.py                 51     29    43%   30, 37, 40-42, 45-88
sentinel\integrations\scanners\http_adapter.py                45      3    93%   28, 35, 39
sentinel\integrations\scanners\network_adapter.py             71     16    77%   32, 39, 43, 53, 86-87, 117-135
sentinel\integrations\threat_feeds\__init__.py                 1      0   100%
sentinel\integrations\threat_feeds\adapters.py               124     33    73%   31, 47, 54, 57, 60-92, 133, 140, 143-145, 148, 157, 196, 203, 206-208, 211, 217
sentinel\integrations\threat_feeds\vulnerability_sync.py      60     18    70%   36, 43, 46, 74-100
sentinel\intelligence\__init__.py                              1      0   100%
sentinel\intelligence\attack_paths\__init__.py                 1      0   100%
sentinel\intelligence\attack_paths\analyzer.py                46      1    98%   67
sentinel\intelligence\correlation\__init__.py                  1      0   100%
sentinel\intelligence\correlation\engine.py                   43      6    86%   50-55
sentinel\intelligence\evaluation\__init__.py                   0      0   100%
sentinel\intelligence\evaluation\harness.py                   87     14    84%   61, 140-141, 158-171, 176, 185
sentinel\intelligence\recommendations\__init__.py              1      0   100%
sentinel\intelligence\recommendations\engine.py               31      2    94%   42, 46
sentinel\intelligence\reporting\generator.py                 142     14    90%   74-76, 80-85, 136, 196, 228, 232-234, 261
sentinel\intelligence\risk\__init__.py                         1      0   100%
sentinel\intelligence\risk\finding_engine.py                 105     18    83%   168, 216, 218, 228-244, 248-265
sentinel\intelligence\risk\risk_engine.py                     44      2    95%   107, 109
sentinel\lab\__init__.py                                       0      0   100%
sentinel\lab\app.py                                           31      6    81%   33, 43-46, 52
sentinel\logging\__init__.py                                   1      0   100%
sentinel\logging\logger.py                                    35      2    94%   28, 48
sentinel\modules\__init__.py                                   1      0   100%
sentinel\modules\api_security\__init__.py                      1      0   100%
sentinel\modules\api_security\adapters.py                    230     43    81%   39, 47, 54, 57-59, 65, 80-81, 84-85, 121, 128, 131-133, 146-147, 204, 211, 214-216, 269-270, 306, 313, 316-318, 341-351, 382, 389, 392-394, 421-431
sentinel\modules\cloud\__init__.py                             1      0   100%
sentinel\modules\cloud\adapters.py                           155     17    89%   59, 64, 82, 90, 97, 100-102, 115, 223, 230, 233, 244, 301, 308, 311, 322
sentinel\modules\dns\__init__.py                               1      0   100%
sentinel\modules\dns\dns_intel.py                             62     16    74%   33, 40, 43-45, 67, 76, 83-92
sentinel\modules\endpoint\__init__.py                          1      0   100%
sentinel\modules\endpoint\adapters.py                        405    151    63%   67-90, 93-121, 124-145, 148-167, 185, 211-212, 235-236, 277-278, 286-287, 306-307, 347-348, 352-371, 393-394, 398-401, 435-438, 456-468, 471-472, 495-496, 500, 503-519, 522, 525-557, 564-579, 736, 744, 756, 759, 791-792, 796-801
sentinel\modules\endpoint\models.py                           68      0   100%
sentinel\modules\forensics\__init__.py                         1      0   100%
sentinel\modules\forensics\adapters.py                       122     16    87%   35, 42, 45-47, 55-56, 116, 123, 126, 132, 167, 175, 182, 185, 191
sentinel\modules\incident_response\__init__.py                 1      0   100%
sentinel\modules\incident_response\adapters.py                66      6    91%   63, 70, 73-75, 89
sentinel\modules\mobile\__init__.py                            1      0   100%
sentinel\modules\mobile\adapters.py                           99     13    87%   36, 44, 51, 54-56, 75-76, 148, 155, 158-160
sentinel\modules\network\__init__.py                           1      0   100%
sentinel\modules\network\adapters.py                         244     52    79%   38, 45, 48-50, 74-75, 80, 113, 121, 128, 131-133, 158-159, 173, 215, 222, 225-227, 288, 295, 298-300, 334-338, 373, 380, 383-385, 397-412
sentinel\modules\operations\alerting.py                       66      7    89%   50-51, 84, 86, 88, 93, 102
sentinel\modules\operations\baseline.py                       69      5    93%   58, 61, 121-122, 149
sentinel\modules\operations\dashboard.py                      30      0   100%
sentinel\modules\operations\scheduler.py                      44     12    73%   66, 69-81
sentinel\modules\recon\__init__.py                             1      0   100%
sentinel\modules\recon\adapters.py                           251     43    83%   36, 43, 46-48, 67, 76-85, 94-96, 134, 141, 145, 181-182, 211, 218, 221-223, 245-247, 278, 285, 289, 296, 327, 329, 338-339, 373, 380, 384
sentinel\modules\recon\graph.py                               93      7    92%   139-145
sentinel\modules\threat_intel\__init__.py                      1      1     0%   3
sentinel\modules\vulnerability\__init__.py                     1      0   100%
sentinel\modules\vulnerability\correlation.py                 46      6    87%   31, 38, 41-43, 59
sentinel\modules\web\__init__.py                               1      0   100%
sentinel\modules\web\adapters.py                             221     41    81%   38, 45, 48-50, 56, 70, 91-92, 124, 132, 139, 142-144, 150, 195-205, 247, 254, 257-259, 265, 286-287, 318, 326, 333, 336-338, 344, 368-369, 390-391, 398-407
sentinel\modules\wireless\__init__.py                          1      0   100%
sentinel\modules\wireless\adapters.py                        128     32    75%   36, 43, 46, 57-65, 103, 111, 118, 121-123, 191, 198, 201-203, 212-221
sentinel\storage\__init__.py                                   1      0   100%
sentinel\storage\artifacts\__init__.py                         1      0   100%
sentinel\storage\artifacts\storage.py                         96     29    70%   26, 31, 36, 41, 75, 88, 113, 124-135, 138-144, 147-151, 154-158, 165
sentinel\storage\database\__init__.py                          1      0   100%
sentinel\storage\database\models.py                          165      0   100%
sentinel\storage\database\session.py                          29     10    66%   21-34, 58-60
sentinel\storage\evidence\__init__.py                          1      0   100%
sentinel\storage\evidence\store.py                           117     10    91%   130, 132, 137, 157, 159, 161, 253, 258, 270, 275
sentinel\storage\repositories\__init__.py                      0      0   100%
sentinel\storage\repositories\factory.py                      36      8    78%   45, 56, 64-70
sentinel\storage\repositories\in_memory.py                    90     34    62%   78-89, 98, 121-128, 133, 136-137, 140-141, 148-155
sentinel\storage\repositories\interfaces.py                    7      0   100%
sentinel\storage\repositories\postgres.py                    164     53    68%   159, 183-188, 191-195, 280-283, 299-310, 313-319, 373, 381-388, 436, 444-451
----------------------------------------------------------------------------------------
TOTAL                                                       7001   1190    83%
134 passed in 220.76s (0:03:40)

```