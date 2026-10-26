-- Crapplet DDoS Shield - ClickHouse schema (Phase 3)
-- Apply with: clickhouse-client --multiquery < 001_schema.sql
-- Retention is enforced by TTL; adjust the INTERVALs to your disk budget.
-- All timestamps are DateTime('UTC'): the collector writes UTC, whatever the server's time zone.

CREATE DATABASE IF NOT EXISTS shield;

-- Per protected destination, per second. Only rows above the collector's store_min_pps.
CREATE TABLE IF NOT EXISTS shield.dst_1s
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
TTL ts + INTERVAL 7 DAY;

-- Inbound / outbound totals per second.
CREATE TABLE IF NOT EXISTS shield.totals_1s
(
    ts         DateTime('UTC') CODEC(DoubleDelta, ZSTD),
    direction  LowCardinality(String),
    pps        Float64,
    bps        Float64,
    tcp_pps    Float64,
    udp_pps    Float64,
    icmp_pps   Float64,
    other_pps  Float64,
    provenance LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (direction, ts)
TTL ts + INTERVAL 30 DAY;

-- Measured interface rates (sFlow counter samples, SNMP).
CREATE TABLE IF NOT EXISTS shield.iface_1s
(
    ts        DateTime('UTC') CODEC(DoubleDelta, ZSTD),
    agent     LowCardinality(String),
    if_index  UInt32,
    if_name   LowCardinality(String),
    in_bps    Float64,
    out_bps   Float64,
    in_pps    Float64,
    out_pps   Float64,
    speed_bps UInt64,
    source    LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (agent, if_index, ts)
TTL ts + INTERVAL 90 DAY;

-- Optional raw (sampled) flow records - disabled by default (store_raw_flows).
CREATE TABLE IF NOT EXISTS shield.flows_raw
(
    ts            DateTime('UTC'),
    kind          LowCardinality(String),
    exporter      LowCardinality(String),
    src           String,
    dst           String,
    proto         UInt8,
    src_port      UInt16,
    dst_port      UInt16,
    tcp_flags     UInt8,
    bytes         UInt64,
    packets       UInt64,
    sampling_rate UInt32,
    duration_ms   UInt32
)
ENGINE = MergeTree
PARTITION BY toStartOfHour(ts)
ORDER BY (dst, ts)
TTL ts + INTERVAL 48 HOUR;

-- 1-minute rollups for long-term history and baselines (Phase 4).
CREATE TABLE IF NOT EXISTS shield.dst_1m
(
    ts       DateTime('UTC'),
    dst      String,
    prefix   LowCardinality(String),
    seconds  AggregateFunction(count),
    pps_avg  AggregateFunction(avg, Float64),
    pps_max  AggregateFunction(max, Float64),
    bps_avg  AggregateFunction(avg, Float64),
    bps_max  AggregateFunction(max, Float64),
    udp_avg  AggregateFunction(avg, Float64),
    syn_avg  AggregateFunction(avg, Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (dst, ts)
TTL ts + INTERVAL 180 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS shield.dst_1m_mv TO shield.dst_1m AS
SELECT toStartOfMinute(ts) AS ts, dst, any(prefix) AS prefix,
       countState() AS seconds,
       avgState(pps) AS pps_avg, maxState(pps) AS pps_max,
       avgState(bps) AS bps_avg, maxState(bps) AS bps_max,
       avgState(udp_pps) AS udp_avg, avgState(syn_pps) AS syn_avg
FROM shield.dst_1s
GROUP BY ts, dst;

CREATE TABLE IF NOT EXISTS shield.totals_1m
(
    ts        DateTime('UTC'),
    direction LowCardinality(String),
    pps_avg   AggregateFunction(avg, Float64),
    pps_max   AggregateFunction(max, Float64),
    bps_avg   AggregateFunction(avg, Float64),
    bps_max   AggregateFunction(max, Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (direction, ts)
TTL ts + INTERVAL 400 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS shield.totals_1m_mv TO shield.totals_1m AS
SELECT toStartOfMinute(ts) AS ts, direction,
       avgState(pps) AS pps_avg, maxState(pps) AS pps_max,
       avgState(bps) AS bps_avg, maxState(bps) AS bps_max
FROM shield.totals_1s
GROUP BY ts, direction;
