package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	rsaEncryptedKeySize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_rsa_encrypted_key_size_bytes",
			Help: "Size of AES key encrypted with RSA in bytes",
		},
	)
	mlkemEncryptedKeySize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_mlkem_encrypted_key_size_bytes",
			Help: "Size of AES key encrypted with ML-KEM in bytes",
		},
	)
	rsaPublicKeySize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_rsa_public_key_size_bytes",
			Help: "Size of RSA public key in bytes",
		},
	)
	mlkemPublicKeySize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_mlkem_public_key_size_bytes",
			Help: "Size of ML-KEM public key in bytes",
		},
	)
	rsaEncryptionDuration = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_rsa_encryption_duration_seconds",
			Help: "Duration of RSA encryption operation in seconds",
		},
	)
	mlkemEncapsulationDuration = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_mlkem_encapsulation_duration_seconds",
			Help: "Duration of ML-KEM encapsulation operation in seconds",
		},
	)
	encryptionDurationRatio = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_encryption_duration_ratio",
			Help: "Ratio of ML-KEM to RSA encryption duration (ML-KEM / RSA)",
		},
	)
	encryptedKeySizeRatio = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_encrypted_key_size_ratio",
			Help: "Ratio of ML-KEM to RSA encrypted key size (ML-KEM / RSA)",
		},
	)
	publicKeySizeRatio = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_public_key_size_ratio",
			Help: "Ratio of ML-KEM to RSA public key size (ML-KEM / RSA)",
		},
	)
	rsaEncryptionDurationAvg = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_rsa_encryption_duration_avg_seconds",
			Help: "Average duration of RSA encryption operations in seconds",
		},
	)
	mlkemEncapsulationDurationAvg = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "client_mlkem_encapsulation_duration_avg_seconds",
			Help: "Average duration of ML-KEM encapsulation operations in seconds",
		},
	)
	encryptionCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "client_encryption_operations_total",
			Help: "Total number of encryption operations",
		},
	)
)

// 平均計算用の累積値
var (
	rsaTotalDuration   float64
	mlkemTotalDuration float64
	operationCount     int
)

// 公開鍵のレスポンス構造体
type PublicKeyResponse struct {
	PublicKey string `json:"public_key"`
	KeySize   int    `json:"key_size"`
}

// 暗号化データの送信構造体
type EncryptedData struct {
	EncryptedAESKey  string `json:"encrypted_aes_key"` // RSAで暗号化されたAES鍵
	EncryptedMessage string `json:"encrypted_message"` // AESで暗号化されたメッセージ
	IV               string `json:"iv"`                // AESの初期化ベクトル
}

func main() {
	// Prometheusメトリクスサーバーを起動
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("メトリクスサーバーを起動: http://localhost:8082/metrics")
		if err := http.ListenAndServe(":8082", nil); err != nil {
			log.Printf("メトリクスサーバーエラー: %v", err)
		}
	}()

	// サーバーが起動するまで待機
	fmt.Println("RSAサーバーの起動を待機中...")
	time.Sleep(3 * time.Second)

	fmt.Println("\n=== ハイブリッド暗号化を1秒毎に実行します ===")

	counter := 0
	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	// 暗号化するメッセージ
	messages := []string{
		"量子コンピュータに対抗するポスト量子暗号",
	}

	for range ticker.C {
		counter++
		message := messages[counter%len(messages)]

		fmt.Printf("\n========== 暗号化 #%d ==========\n", counter)
		startTime := time.Now()
		encryptionCounter.Inc()

		// Step 1: RSA公開鍵を取得
		rsaPublicKey, rsaPubKeyBytes, err := fetchPublicKey("http://rsa-server:8080/public-key")
		if err != nil {
			log.Printf("RSA公開鍵の取得に失敗: %v", err)
			continue
		}
		rsaPublicKeySize.Set(float64(len(rsaPubKeyBytes)))
		fmt.Printf("[%s] ✓ RSA公開鍵を取得 (%dバイト)\n", time.Since(startTime), len(rsaPubKeyBytes))

		// Step 1.5: ML-KEM公開鍵も取得
		mlkemPublicKey, mlkemPubKeyBytes, err := fetchMLKEMPublicKey("http://ml-kem-server:8081/public-key")
		if err != nil {
			log.Printf("ML-KEM公開鍵の取得に失敗: %v", err)
			continue
		}
		mlkemPublicKeySize.Set(float64(len(mlkemPubKeyBytes)))
		fmt.Printf("[%s] ✓ ML-KEM公開鍵を取得 (%dバイト)\n", time.Since(startTime), len(mlkemPubKeyBytes))

		// Step 2: AES鍵を生成（256ビット = 32バイト）
		aesKey := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
			log.Printf("AES鍵の生成に失敗: %v", err)
			continue
		}
		fmt.Printf("[%s] ✓ AES-256鍵を生成\n", time.Since(startTime))

		// Step 3: AESでメッセージを暗号化
		encryptedMessage, iv, err := encryptAES([]byte(message), aesKey)
		if err != nil {
			log.Printf("AES暗号化に失敗: %v", err)
			continue
		}
		fmt.Printf("[%s] ✓ メッセージをAES暗号化 (%dバイト)\n", time.Since(startTime), len(encryptedMessage))

		// Step 4: RSAでAES鍵を暗号化
		rsaEncryptStart := time.Now()
		rsaEncryptedAESKey, err := encryptRSA(rsaPublicKey, aesKey)
		rsaEncryptDuration := time.Since(rsaEncryptStart)
		if err != nil {
			log.Printf("RSA暗号化に失敗: %v", err)
			continue
		}
		rsaEncryptedKeySize.Set(float64(len(rsaEncryptedAESKey)))
		rsaEncryptionDuration.Set(rsaEncryptDuration.Seconds())
		fmt.Printf("[%s] ✓ AES鍵をRSA暗号化 (%dバイト, %v)\n", time.Since(startTime), len(rsaEncryptedAESKey), rsaEncryptDuration)

		// Step 5: ML-KEMでAES鍵をカプセル化
		mlkemEncapsulateStart := time.Now()
		mlkemCiphertext, _, err := encryptMLKEM(mlkemPublicKey, aesKey)
		mlkemEncapsulateDuration := time.Since(mlkemEncapsulateStart)
		if err != nil {
			log.Printf("ML-KEM暗号化に失敗: %v", err)
			continue
		}
		mlkemEncryptedKeySize.Set(float64(len(mlkemCiphertext)))
		mlkemEncapsulationDuration.Set(mlkemEncapsulateDuration.Seconds())
		fmt.Printf("[%s] ✓ AES鍵をML-KEM暗号化 (%dバイト, %v)\n", time.Since(startTime), len(mlkemCiphertext), mlkemEncapsulateDuration)

		// 累積平均を計算
		operationCount++
		rsaTotalDuration += rsaEncryptDuration.Seconds()
		mlkemTotalDuration += mlkemEncapsulateDuration.Seconds()
		rsaAvg := rsaTotalDuration / float64(operationCount)
		mlkemAvg := mlkemTotalDuration / float64(operationCount)
		rsaEncryptionDurationAvg.Set(rsaAvg)
		mlkemEncapsulationDurationAvg.Set(mlkemAvg)

		// 比較値を計算してメトリクスに記録
		if rsaEncryptDuration.Seconds() > 0 {
			durationRatio := mlkemEncapsulateDuration.Seconds() / rsaEncryptDuration.Seconds()
			encryptionDurationRatio.Set(durationRatio)
		}
		if len(rsaEncryptedAESKey) > 0 {
			keySizeRatio := float64(len(mlkemCiphertext)) / float64(len(rsaEncryptedAESKey))
			encryptedKeySizeRatio.Set(keySizeRatio)
		}
		if len(rsaPubKeyBytes) > 0 {
			pubKeySizeRatio := float64(len(mlkemPubKeyBytes)) / float64(len(rsaPubKeyBytes))
			publicKeySizeRatio.Set(pubKeySizeRatio)
		}

		// 結果のサマリー
		totalTime := time.Since(startTime)
		fmt.Printf("[%s] ✅ ハイブリッド暗号化完了\n", totalTime)
		fmt.Printf("メッセージ: \"%s\"\n", message[:min(len(message), 30)]+"...")
		fmt.Printf("📊 RSA公開鍵: %d バイト\n", len(rsaPubKeyBytes))
		fmt.Printf("📊 ML-KEM公開鍵: %d バイト\n", len(mlkemPubKeyBytes))
		fmt.Printf("📊 RSA暗号化AES鍵: %d バイト\n", len(rsaEncryptedAESKey))
		fmt.Printf("📊 ML-KEM暗号化AES鍵: %d バイト\n", len(mlkemCiphertext))
		fmt.Printf("📊 暗号文: %d バイト, IV: %d バイト\n", len(encryptedMessage), len(iv))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RSA公開鍵を取得
func fetchPublicKey(url string) (*rsa.PublicKey, []byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP GETエラー: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTPステータスエラー: %d", resp.StatusCode)
	}

	var pubKeyResp PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&pubKeyResp); err != nil {
		return nil, nil, fmt.Errorf("JSONデコードエラー: %w", err)
	}

	// Base64デコード
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyResp.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Base64デコードエラー: %w", err)
	}

	// 公開鍵をパース
	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("公開鍵のパースエラー: %w", err)
	}

	publicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("RSA公開鍵への変換エラー")
	}

	return publicKey, pubKeyBytes, nil
}

// ML-KEM公開鍵を取得
func fetchMLKEMPublicKey(url string) (*kyber768.PublicKey, []byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP GETエラー: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTPステータスエラー: %d", resp.StatusCode)
	}

	var pubKeyResp struct {
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
		KeySize   int    `json:"key_size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pubKeyResp); err != nil {
		return nil, nil, fmt.Errorf("JSONデコードエラー: %w", err)
	}

	// Base64デコード
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyResp.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Base64デコードエラー: %w", err)
	}

	// ML-KEM公開鍵をデシリアライズ
	scheme := kyber768.Scheme()
	publicKey, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("公開鍵のデシリアライズエラー: %w", err)
	}

	mlkemPublicKey, ok := publicKey.(*kyber768.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("ML-KEM公開鍵への変換エラー")
	}

	return mlkemPublicKey, pubKeyBytes, nil
}

// AESでデータを暗号化（AES-256-CBC）
func encryptAES(plaintext []byte, key []byte) ([]byte, []byte, error) {
	// AES暗号ブロックを作成
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// パディングを追加
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	// 初期化ベクトル（IV）を生成
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	// CBCモードで暗号化
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, iv, nil
}

// RSAで鍵を暗号化（OAEP）
func encryptRSA(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, data, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// ML-KEMでカプセル化（暗号化）
func encryptMLKEM(publicKey *kyber768.PublicKey, data []byte) ([]byte, []byte, error) {
	scheme := kyber768.Scheme()
	// カプセル化: 共有秘密鍵とカプセル化テキストを生成
	ciphertext, sharedSecret, err := scheme.Encapsulate(publicKey)
	if err != nil {
		return nil, nil, err
	}
	// 実際のアプリケーションでは、sharedSecretを使ってdataを暗号化する
	// ここでは比較のためカプセル化テキストのサイズを測定
	return ciphertext, sharedSecret, nil
}
