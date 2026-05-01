# Instructor answer key

## Core story

The lab models the defensive implications of Unit 42's Iran cyber risk brief: conflict-themed phishing/fraud, hacktivist disruption, OT/ICS targeting, and destructive/wiper risk.

## Must-find indicators

- `CL-STA-1128`, `Cyber Av3ngers`, `Storm-0784`
- `FactoryTalk`, `Allen-Bradley`, `Rockwell Automation`
- `iranforward.org`, `trumpvsirancoin.xyz`, `emiratescryptobank.com`, `emiratesinvestunion.com`
- `Starlink/VSAT`
- `ddos_spike`
- `wiper_execution`

## Good student outcomes

- Separates phishing/fraud, OT targeting, DDoS, and wiper activity into distinct detection classes
- Builds a timeline across multiple source types
- Notes that generated lab domains/events are synthetic and article-inspired
- Includes false-positive handling for OT inventory scans and high-volume benign traffic
