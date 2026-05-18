# Domain Modes

ThreatLib can run as a general risk engine, but production teams usually need sharper defaults for a specific product surface. Domain modes provide that layer without changing detector semantics.

The first domain-mode set covers:

- `social_media`
- `chat_app`
- `gaming`

Each mode defines the adapter, attack-vector focus, feature restriction map, high-impact actions, detector weight adjustments, expected event coverage, calibration requirements, domain-native behavioral detectors, and scenario-level playbook detection.

## Why Domain Modes Exist

A social feed, a private messaging product, and a multiplayer game can all receive `account_id`, device, network, timing, report, and event data. The meaning of the actions differs.

On a social media app, a new account posting external links and rapidly messaging strangers is a direct phishing and coordinated-amplification concern. On a chat app, message forwarding, broadcast messaging, link sharing, and group creation are more important. In a game, the primary risks include automation, account farming, item-trade abuse, ranked-match manipulation, harassment, and session anomalies.

Domain modes tune the policy surface for those differences and now add detectors that score the native workflows directly. They do not remove the uncertainty contract, quorum, shadow mode, audit logging, or privacy rules.

## Domain-Native Detection

The general detector set remains active in every mode. Domain-native detectors add evidence when the product supplies events that are meaningful only inside a specific workflow.

`social_behavior` looks for social-feed and outreach patterns: follow-to-DM funnels, high link density in DMs, many distinct outreach targets, posting or sharing far more than consuming, and social shares concentrated on a single external domain. It can also emit weak legitimate evidence when an account explores profiles or content before limited low-link outreach.

`chat_abuse` looks for messaging-specific abuse: forward-dominated communication, broadcast messages carrying links, rapid group creation or member seeding, multi-recipient link fan-out, one-way outbound messaging, and high-volume call fan-out. It can emit weak legitimate evidence for reciprocal low-link conversations.

`gaming_integrity` looks for game-native abuse: repeated short match loops, new accounts entering ranked play at high velocity, early virtual-goods movement, high normalized economy value moved by a new account, player-report density tied to chat, party or guild activity tied to trading, and repeated match-result patterns. It can emit weak legitimate evidence for normal match play without early economy movement or reports.

`domain_scenario` runs after the domain-native detectors and looks for complete attack playbooks. In social mode it recognizes profile-to-DM phishing funnels, comment redirect campaigns, new-account amplification clusters, creator impersonation outreach, and agreement between behavior and HMM intent. In chat mode it recognizes forward cascades, new-account group seeding, broadcast fan-out, link-campaign alignment, and minor-safety outreach scenarios. In gaming mode it recognizes ranked short-loop farming, new-account economy mule behavior, reported chat harassment, party or guild economy coordination, and alignment between gaming integrity and account-age velocity.

These detectors return `DetectorResult.uncertain()` when the relevant event surface is absent. They do not infer that a product is safe because it does not send social, chat, or game events.

## Commands

List modes:

```bash
threatlib-domain list
```

Inspect a mode:

```bash
threatlib-domain show social_media
threatlib-domain show chat_app
threatlib-domain show gaming
```

Inspect calibration requirements:

```bash
threatlib-domain calibration social_media
```

Write a domain-specific policy:

```bash
threatlib-domain apply chat_app --base threatlib.yaml --output policies/chat-app.yaml
```

## API

The API exposes the same information:

```bash
curl http://127.0.0.1:8000/domains
curl http://127.0.0.1:8000/domains/social_media
curl http://127.0.0.1:8000/domains/social_media/policy-preview
curl http://127.0.0.1:8000/domains/social_media/calibration
```

## Social Media Mode

`social_media` focuses on feed, profile, follow graph, comments, DMs, and external links.

Primary attack paths:

- automated bot creation
- fake identity
- DM phishing
- external redirect campaigns
- coordinated inauthentic behavior
- misinformation seeding
- harassment campaigns
- Sybil attacks
- compromised legitimate accounts
- scraping and API abuse

The mode raises emphasis on content signals, external link patterns, HMM intent, community detection, coordinated behavior, report history, graph distance, and `social_behavior`. It also expands the feature restriction map to include comments, follows, content posts, DMs, shares, groups, and mass invites.

Calibration requires a longer shadow period because social products often have uneven behavior distributions across creators, lurkers, moderators, and high-volume legitimate users.

## Chat App Mode

`chat_app` focuses on direct messages, group messages, forwards, broadcasts, calls, and links.

Primary attack paths:

- account takeover
- DM phishing
- fake giveaway links
- group-based coordination
- misinformation forwarding
- harassment
- child-safety escalation
- scraping and API abuse

The mode raises emphasis on content signals, external link concentration, HMM intent, report history, session anomaly, graph distance, coordinated behavior, and `chat_abuse`. The feature restriction map is centered on message sending, forwarding, group creation, group addition, link sharing, calls, and broadcast messaging.

Calibration reviews should include forward-event coverage and link-domain coverage because a private messaging product may have fewer public graph signals than a social network.

## Gaming Mode

`gaming` focuses on matchmaking, party chat, item trading, guilds, leaderboards, and player reports.

Primary attack paths:

- bot account creation
- account takeover
- coordinated abuse
- harassment
- Sybil account farms
- compromised accounts
- API abuse and scraping

The mode raises emphasis on behavioral timing, IP network signals, session anomaly, account-age velocity, graph distance, community detection, HMM intent, report history, `gaming_integrity`, and optional ML model evidence. The feature restriction map includes ranked matchmaking, chat, item trading, gifting, parties, guilds, looking-for-group posts, and reporting.

Calibration reviews should include session-event coverage and economy-event coverage. Gaming systems can often collect high event volume quickly, but labels for true abuse still require human or backend confirmation.

## Calibration Readiness

Every domain mode returns a calibration plan with:

- shadow observation hours
- minimum scored accounts
- minimum labeled outcomes
- minimum confirmed positive labels
- target false-positive rate
- target recall
- signal coverage targets
- readiness checklist

These values are conservative starting points. They are not final production thresholds. Operators should run replay against historical data, review false-positive candidates, and compare domain-mode action distributions before disabling shadow mode.
