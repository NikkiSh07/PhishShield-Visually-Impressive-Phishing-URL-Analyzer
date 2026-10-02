-- ============================================================
-- PhishShield MySQL Schema
-- Run: mysql -u root -p < schema.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS phishshield
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE phishshield;

-- --------------------------------------------------------
-- Table 1: scan_logs — one row per URL analysis request
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_logs (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    url           TEXT NOT NULL,
    hostname      VARCHAR(255) NOT NULL,
    score         TINYINT UNSIGNED NOT NULL DEFAULT 0,
    level         ENUM('LOW RISK', 'MEDIUM RISK', 'HIGH RISK') NOT NULL,
    color         VARCHAR(10) NOT NULL DEFAULT '#00E676',
    description   TEXT,
    dns_resolves  TINYINT(1) DEFAULT NULL,
    whois_age     INT DEFAULT NULL,          -- domain age in days (NULL if unknown)
    whois_created DATE DEFAULT NULL,
    ml_score      TINYINT UNSIGNED DEFAULT NULL,
    ml_label      VARCHAR(20) DEFAULT NULL,
    ml_prob       FLOAT DEFAULT NULL,
    java_entropy  FLOAT DEFAULT NULL,        -- Java-computed domain entropy
    java_digit_ratio  FLOAT DEFAULT NULL,
    java_special_chars INT DEFAULT NULL,
    java_ngram_score   FLOAT DEFAULT NULL,
    client_ip     VARCHAR(45) DEFAULT NULL,
    analyzed_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_hostname (hostname(100)),
    INDEX idx_score    (score),
    INDEX idx_level    (level),
    INDEX idx_analyzed (analyzed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- Table 2: scan_signals — individual detection signal rows
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_signals (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id    INT UNSIGNED NOT NULL,
    signal_text TEXT NOT NULL,
    points     TINYINT UNSIGNED NOT NULL DEFAULT 0,
    type       ENUM('triggered', 'safe', 'neutral') NOT NULL DEFAULT 'neutral',
    icon       VARCHAR(10) NOT NULL DEFAULT '—',
    sort_order TINYINT UNSIGNED NOT NULL DEFAULT 0,
    CONSTRAINT fk_signals_scan
        FOREIGN KEY (scan_id) REFERENCES scan_logs(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_scan_id (scan_id),
    INDEX idx_type    (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- Table 3: scan_breakdown — heuristic category breakdown
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_breakdown (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id    INT UNSIGNED NOT NULL,
    name       VARCHAR(80) NOT NULL,
    pts        TINYINT UNSIGNED NOT NULL DEFAULT 0,
    max_pts    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    CONSTRAINT fk_breakdown_scan
        FOREIGN KEY (scan_id) REFERENCES scan_logs(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_scan_id (scan_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- Useful views
-- --------------------------------------------------------

-- Daily stats view
CREATE OR REPLACE VIEW v_daily_stats AS
SELECT
    DATE(analyzed_at)          AS scan_date,
    COUNT(*)                   AS total_scans,
    AVG(score)                 AS avg_score,
    SUM(level = 'HIGH RISK')   AS high_risk_count,
    SUM(level = 'MEDIUM RISK') AS medium_risk_count,
    SUM(level = 'LOW RISK')    AS low_risk_count
FROM scan_logs
GROUP BY DATE(analyzed_at)
ORDER BY scan_date DESC;

-- Top phishing domains view
CREATE OR REPLACE VIEW v_top_phishing AS
SELECT
    hostname,
    COUNT(*)       AS scan_count,
    MAX(score)     AS max_score,
    AVG(score)     AS avg_score,
    MAX(analyzed_at) AS last_seen
FROM scan_logs
WHERE level = 'HIGH RISK'
GROUP BY hostname
ORDER BY scan_count DESC
LIMIT 50;
