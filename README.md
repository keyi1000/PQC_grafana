# RSA vs ML-KEM (Kyber) ハイブリッド暗号化システム

3 つのコンテナで構成されるハイブリッド暗号化のデモシステムです。

## コンテナ構成

1. **rsa-public-key-server** (ポート 8090)

   - RSA-2048 公開鍵サーバー
   - `/public-key` - RSA 公開鍵を JSON 形式で提供
   - `/metrics` - Prometheus メトリクス

2. **ml-kem-public-key-server** (ポート 8091)

   - ML-KEM-768 (Kyber) 公開鍵サーバー
   - `/public-key` - ML-KEM 公開鍵を JSON 形式で提供
   - `/metrics` - Prometheus メトリクス

3. **aes-encryption-client**
   - AES-256-CBC でデータを暗号化
   - RSA 公開鍵で AES 鍵を暗号化

## 起動方法

```bash
# コンテナをビルド・起動
docker compose up --build -d

# ログを確認
docker compose logs -f

# 停止
docker compose down
```

## メトリクスの確認

各サーバーのメトリクスエンドポイント：

```bash
# RSAサーバーのメトリクス
curl http://localhost:8090/metrics

# ML-KEMサーバーのメトリクス
curl http://localhost:8091/metrics
```

### 収集されるメトリクス

**RSA サーバー:**

- `rsa_server_http_requests_total` - HTTP リクエスト総数
- `rsa_server_http_request_duration_seconds` - リクエスト処理時間
- `rsa_server_public_key_requests_total` - 公開鍵リクエスト総数
- `rsa_server_key_generation_seconds` - 鍵生成時間

**ML-KEM サーバー:**

- `mlkem_server_http_requests_total` - HTTP リクエスト総数
- `mlkem_server_http_request_duration_seconds` - リクエスト処理時間
- `mlkem_server_public_key_requests_total` - 公開鍵リクエスト総数
- `mlkem_server_key_generation_seconds` - 鍵生成時間

## Prometheus 設定

既存の Prometheus に以下のスクレイプ設定を追加してください：

**重要**: Docker コンテナのサービスにアクセスするため、`localhost`ではなくホストマシンの IP アドレスを使用してください。

```yaml
scrape_configs:
  - job_name: "rsa-server"
    static_configs:
      - targets: ["10.200.1.89:8090"] # ホストマシンのIPアドレスを使用
    metrics_path: "/metrics"

  - job_name: "ml-kem-server"
    static_configs:
      - targets: ["10.200.1.89:8091"] # ホストマシンのIPアドレスを使用
    metrics_path: "/metrics"
```

**別の方法（macOS の場合）:**

```yaml
scrape_configs:
  - job_name: "rsa-server"
    static_configs:
      - targets: ["host.docker.internal:8090"]
    metrics_path: "/metrics"

  - job_name: "ml-kem-server"
    static_configs:
      - targets: ["host.docker.internal:8091"]
    metrics_path: "/metrics"
```

## Grafana ダッシュボード

### 推奨パネル

1. **鍵生成時間の比較**

   - Query: `rsa_server_key_generation_seconds` vs `mlkem_server_key_generation_seconds`
   - Type: Gauge

2. **リクエスト処理時間**

   - Query: `rate(rsa_server_http_request_duration_seconds_sum[5m])`
   - Query: `rate(mlkem_server_http_request_duration_seconds_sum[5m])`
   - Type: Graph

3. **リクエスト総数**

   - Query: `rsa_server_http_requests_total`
   - Query: `mlkem_server_http_requests_total`
   - Type: Counter

4. **公開鍵リクエスト数**
   - Query: `rsa_server_public_key_requests_total`
   - Query: `mlkem_server_public_key_requests_total`
   - Type: Counter

## テスト方法

```bash
# RSA公開鍵を取得
curl http://localhost:8090/public-key

# ML-KEM公開鍵を取得
curl http://localhost:8091/public-key

# 負荷テスト（10回リクエスト）
for i in {1..10}; do curl http://localhost:8090/public-key; done
for i in {1..10}; do curl http://localhost:8091/public-key; done
```

## 鍵サイズの比較

- **RSA-2048 公開鍵**: 約 270 バイト
- **ML-KEM-768 公開鍵**: 1,184 バイト
- **ML-KEM-768 秘密鍵**: 2,400 バイト

## 技術スタック

- Go 1.23
- Docker & Docker Compose
- Prometheus (メトリクス収集)
- Grafana (可視化)
- github.com/prometheus/client_golang
- github.com/cloudflare/circl (ML-KEM 実装)
# PQC_grafana
