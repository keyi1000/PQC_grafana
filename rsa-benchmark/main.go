package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Prometheusメトリクス
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rsa_server_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"endpoint", "method"},
	)
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rsa_server_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)
	publicKeyRequests = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "rsa_server_public_key_requests_total",
			Help: "Total number of public key requests",
		},
	)
	keyGenerationTime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "rsa_server_key_generation_seconds",
			Help: "Time taken to generate RSA key pair in seconds",
		},
	)
	keyGenerationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "rsa_server_key_generation_duration_seconds",
			Help:    "Histogram of RSA key generation duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	)
)

// 公開鍵のレスポンス構造体
type PublicKeyResponse struct {
	PublicKey string `json:"public_key"`
	KeySize   int    `json:"key_size"`
}

func main() {
	// HTTPサーバーのハンドラーを設定
	http.HandleFunc("/public-key", metricsMiddleware("public-key", getPublicKeyHandler))
	http.HandleFunc("/", metricsMiddleware("index", indexHandler))
	http.Handle("/metrics", promhttp.Handler())

	// サーバーを起動
	port := ":8080"
	fmt.Printf("\nサーバーを起動しました: http://localhost%s\n", port)
	fmt.Println("エンドポイント:")
	fmt.Println("  GET /public-key - RSA公開鍵を取得")
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
		httpRequestsTotal.WithLabelValues(endpoint, r.Method).Inc()

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
		<title>RSA公開鍵サーバー</title>
	</head>
	<body>
	publicKeyRequests.Inc()

		<h1>RSA公開鍵サーバー</h1>
		<p>このサーバーはRSA公開鍵を提供します。</p>
		<h2>使用方法:</h2>
		<ul>
			<li><a href="/public-key">GET /public-key</a> - RSA公開鍵を取得</li>
		</ul>
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

	// リクエストごとに新しいRSA鍵ペアを生成
	startTime := time.Now()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "鍵生成に失敗しました", http.StatusInternalServerError)
		log.Println("鍵生成エラー:", err)
		return
	}
	publicKey := &privateKey.PublicKey
	generationDuration := time.Since(startTime)
	keyGenerationTime.Set(generationDuration.Seconds())
	keyGenerationDuration.Observe(generationDuration.Seconds())
	log.Printf("新しいRSA鍵ペアを生成しました (鍵生成時間: %v)\n", generationDuration)

	// 公開鍵をDER形式にエンコード
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
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
		KeySize:   2048,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("JSONエンコードエラー:", err)
	}

	log.Printf("公開鍵を送信しました (クライアント: %s)\n", r.RemoteAddr)
}
