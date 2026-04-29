# Grading Rubric

Total: 100 points

## 1) IOC detections (30 points)
- 10: Correct domain/IP detection
- 10: Correct package/version detection
- 10: Query quality and low-noise tuning

## 2) Behavioral + correlation quality (35 points)
- 15: Detects postinstall-to-interpreter execution pattern
- 20: Correct correlation of package + process + network in window

## 3) Kibana + ES|QL implementation (20 points)
- 10: ES|QL hunt queries produce expected evidence
- 10: Kibana rule + dashboard/Discover evidence complete

## 4) Analyst report + ATT&CK mapping (15 points)
- 10: Clear, concise incident narrative with decisions
- 5: Accurate ATT&CK mapping and response recommendations

## Deductions
- -5 to -15: high false positives with no tuning rationale
- -5 to -10: missing equivalent query in one platform
- -5: missing evidence for claimed detection
