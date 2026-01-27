package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Prometheusメトリクス
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mlkem_server_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)
	publicKeyRequests = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mlkem_server_public_key_requests_total",
			Help: "Total number of public key requests",
		},
	)
	keyGenerationTime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "mlkem_server_key_generation_seconds",
			Help: "Time taken to generate ML-KEM key pair in seconds",
		},
	)
	keyGenerationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "mlkem_server_key_generation_duration_seconds",
			Help:    "Histogram of ML-KEM key generation duration in seconds",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
		},
	)
)

// 公開鍵のレスポンス構造体
type PublicKeyResponse struct {
	PublicKey string `json:"public_key"`
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
}

func main() {
	// HTTPサーバーのハンドラーを設定
	http.HandleFunc("/public-key", metricsMiddleware("public-key", getPublicKeyHandler))
	http.HandleFunc("/", metricsMiddleware("index", indexHandler))
	http.Handle("/metrics", promhttp.Handler())

	// サーバーを起動
	port := ":8081"
	fmt.Printf("\nサーバーを起動しました: http://localhost%s\n", port)
	fmt.Println("エンドポイント:")
	fmt.Println("  GET /public-key - ML-KEM公開鍵を取得")
	fmt.Println("  GET /metrics - Prometheusメトリクス")
	fmt.Println("\nサーバーを停止するには Ctrl+C を押してください")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("サーバー起動エラー:", err)
	}
}

// メトリクス収集用ミドルウェア
func metricsMiddleware(endpoint string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next(w, r)

		duration := time.Since(start)
		httpRequestDuration.WithLabelValues(endpoint).Observe(duration.Seconds())
	}
}

// インデックスページのハンドラー
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>ML-KEM公開鍵サーバー</title>
	</head>
	<body>
		<h1>ML-KEM (Kyber-768) 公開鍵サーバー</h1>
		<p>このサーバーはポスト量子暗号のML-KEM公開鍵を提供します。</p>
		<h2>使用方法:</h2>
		<ul>
			<li><a href="/public-key">GET /public-key</a> - ML-KEM公開鍵を取得</li>
			<li><a href="/metrics">GET /metrics</a> - Prometheusメトリクス</li>
		</ul>
		<h2>ML-KEMについて:</h2>
		<p>ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) は、NISTが標準化したポスト量子暗号アルゴリズムです。</p>
		<p>量子コンピュータの攻撃にも耐性があります。</p>
	</body>
	</html>
	`
	fmt.Fprint(w, html)
}

// 公開鍵を返すハンドラー
func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GETメソッドのみサポートしています", http.StatusMethodNotAllowed)
		return
	}

	publicKeyRequests.Inc()

	// リクエストごとに新しいML-KEM鍵ペアを生成
	startTime := time.Now()
	publicKey, _, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		http.Error(w, "鍵生成に失敗しました", http.StatusInternalServerError)
		log.Println("鍵生成エラー:", err)
		return
	}
	generationDuration := time.Since(startTime)
	keyGenerationTime.Set(generationDuration.Seconds())
	keyGenerationDuration.Observe(generationDuration.Seconds())
	log.Printf("新しいML-KEM鍵ペアを生成しました (鍵生成時間: %v)\n", generationDuration)

	// 公開鍵をバイナリ形式にシリアライズ
	pubKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		http.Error(w, "公開鍵のエンコードに失敗しました", http.StatusInternalServerError)
		log.Println("公開鍵エンコードエラー:", err)
		return
	}

	// Base64エンコード
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// JSONレスポンスを作成
	response := PublicKeyResponse{
		PublicKey: pubKeyBase64,
		Algorithm: "ML-KEM-768 (Kyber-768)",
		KeySize:   len(pubKeyBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("JSONエンコードエラー:", err)
	}

	log.Printf("ML-KEM公開鍵を送信しました (クライアント: %s)\n", r.RemoteAddr)
}
