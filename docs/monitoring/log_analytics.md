# Monitorix Log Analytics & ELK Integration

This guide explains how to centralize and analyze Monitorix forensics using the ELK Stack (Elasticsearch, Logstash, Kibana) or OpenSearch.

## 1. Architectural Overview
Monitorix can stream events to Logstash using the `siem_service`. Logstash then indexes these events into Elasticsearch for real-time visualization in Kibana.

## 2. Logstash Configuration
Create a `monitorix.conf` file for your Logstash instance:

```ruby
input {
  http {
    port => 5044
    codec => json
  }
}

filter {
  if [event_type] == "Security Alert" {
    mutate { add_tag => ["security_critical"] }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "monitorix-events-%{+YYYY.MM.dd}"
    user => "logstash_internal"
    password => "${LOGSTASH_PASSWORD}"
  }
}
```

## 3. Kibana Dashboards
Once data is flowing, you can build dashboards to visualize:
- **Global Threat Map**: Geolocation of agents reporting alerts.
- **Top 10 Vulnerable Agents**: Fleet-wide vulnerability distribution.
- **Data Exfiltration Trends**: Volume of blocked file transfers over time.

## 4. Performance Benchmarking
Monitorix exposes raw performance data via Prometheus (`/metrics`). Use the **Prometheus DataSource** in Grafana to visualize:
- **API Response P95**: `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))`
- **Agent Heartbeat Success Rate**: `rate(agent_heartbeat_total{status="success"}[5m])`
