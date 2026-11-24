-- Crapplet DDoS Shield - outbound attacks (v1.1.0). Safe to run repeatedly.
--
-- Outbound = traffic FROM an address inside the protected prefixes TO an address outside them
-- (for example a customer server that is part of a botnet, or an open resolver used as an
-- amplifier). The router must export flows for that direction too (see docs/outbound.md).

-- Per local sender, per second. Same columns as dst_1s; here "dst" is the LOCAL SENDER and
-- sources_est the number of distinct outside addresses it sent to.
CREATE TABLE IF NOT EXISTS shield.out_1s
(
    ts           DateTime('UTC') CODEC(DoubleDelta, ZSTD),
    dst          String,
    prefix       LowCardinality(String),
    pps          Float64 CODEC(Gorilla, ZSTD),
    bps          Float64 CODEC(Gorilla, ZSTD),
    flow_records Float32,
    tcp_pps      Float64 CODEC(Gorilla, ZSTD),
    udp_pps      Float64 CODEC(Gorilla, ZSTD),
    icmp_pps     Float64 CODEC(Gorilla, ZSTD),
    other_pps    Float64 CODEC(Gorilla, ZSTD),
    syn_pps      Float64 CODEC(Gorilla, ZSTD),
    ack_pps      Float64 CODEC(Gorilla, ZSTD),
    rst_pps      Float64 CODEC(Gorilla, ZSTD),
    frag_pps     Float64 CODEC(Gorilla, ZSTD),
    reflect      Map(String, Float64),
    sources_est  Float32,
    provenance   LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (dst, ts)
TTL ts + INTERVAL 30 DAY;

-- The busiest outside targets of each busy or attacking local sender, per 10-second window.
-- Same columns as src_10s; here "dst" is the LOCAL SENDER and "src" the OUTSIDE TARGET
-- (src_as is 0: Shield looks the target's AS up when reading).
CREATE TABLE IF NOT EXISTS shield.out_targets_10s
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

-- Outbound traffic of each busy or attacking local sender per target network (AS).
CREATE TABLE IF NOT EXISTS shield.out_asn_10s
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
