-- Crapplet DDoS Shield - attack history and sources (v0.8.2). Safe to run repeatedly.

-- Keep per-second destination traffic for 30 days (was 7), so attack graphs stay detailed for a month.
-- One-minute rollups (dst_1m) keep 180 days.
ALTER TABLE shield.dst_1s MODIFY TTL ts + INTERVAL 30 DAY;

-- Busiest source addresses of each busy or attacked destination, per 10-second window.
-- Written by the collector (sources.* in collector.json). The source AS is filled only when the
-- router exports it; Shield otherwise looks the AS up from its IP-to-ASN database when reading.
CREATE TABLE IF NOT EXISTS shield.src_10s
(
    ts            DateTime('UTC') CODEC(DoubleDelta, ZSTD),
    dst           String,
    prefix        LowCardinality(String),
    src           String,
    src_as        UInt32,
    pps           Float64 CODEC(Gorilla, ZSTD),
    bps           Float64 CODEC(Gorilla, ZSTD),
    proto         UInt8,
    src_port      UInt16,
    dst_port      UInt16,
    dst_pps       Float64 CODEC(Gorilla, ZSTD),
    sources       UInt32,
    untracked_pps Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (dst, ts, src)
TTL ts + INTERVAL 90 DAY;

-- Attack traffic per source network (origin AS) of each busy or attacked destination, per
-- 10-second window. Covers every packet, also sources not listed individually in src_10s.
-- asn 4294967294 = not in the IP-to-ASN table (or no table installed); 4294967295 = all networks
-- beyond the 100 largest in that window; 0 = address space nobody announces.
CREATE TABLE IF NOT EXISTS shield.asn_10s
(
    ts      DateTime('UTC') CODEC(DoubleDelta, ZSTD),
    dst     String,
    prefix  LowCardinality(String),
    asn     UInt32,
    country LowCardinality(String),
    pps     Float64 CODEC(Gorilla, ZSTD),
    bps     Float64 CODEC(Gorilla, ZSTD),
    sources UInt32,
    dst_pps Float64 CODEC(Gorilla, ZSTD)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (dst, ts, asn)
TTL ts + INTERVAL 90 DAY;
