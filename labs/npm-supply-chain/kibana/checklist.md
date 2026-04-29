# Kibana Practical Checklist

## Discover investigation (required)
- [ ] Find first package install event for compromised versions
- [ ] Pivot to related process events on same host
- [ ] Pivot to outbound DNS/proxy/network events within 30 minutes
- [ ] Document impacted hosts/users

## ES|QL hunting (required)
- [ ] Run IOC query and export results
- [ ] Run behavioral query and identify execution chain
- [ ] Run correlation query and identify high-confidence alerts

## Elastic Security rule creation (required)
- [ ] Create IOC rule (low/medium severity)
- [ ] Create behavioral rule (medium/high severity)
- [ ] Create correlation rule (high severity)
- [ ] Set investigation guide and triage notes in rule metadata

## Required visualizations
- [ ] Timeline of events by host
- [ ] Top suspicious processes
- [ ] Domain/IP destination chart
- [ ] File artifact hits by OS
