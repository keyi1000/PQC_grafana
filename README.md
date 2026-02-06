
PQC_grafana

## 1. 研究概要
今回はRSAとML-KEMとの違いを比較することで明確にした

## 2. 研究背景
暗号化について調べていくなけで耐量子暗号について理解を深めたいと感じたからです。

## 3. 研究目的
- 耐量子暗号とPQCとの違いを比較する

## 4. 提案手法
本研究では、prometheusとgrafanaというツールを使い鍵の生成時間や鍵のサイズなどを比較する。

## 5. システム構成
- バックエンド：
- 使用言語：Go

## 6. 機能一覧
- 機能1： http://localhost:8090/metrics
- 機能2： http://localhost:8091/metrics
- 機能3： http://localhost:8092/metrics

上記にリクエストを送ると各データがレスポンンスされる

## 7. 実行方法

```
docker compose up 
```
このリポジトリにはないがprometheusとgrafanの環境を用意しデータを読み取る

## 8. 評価・結果
実験の結果、rsaとml-kemの違いがわかり十分に勉強できたと感じている。
特に顕著なのはrsaは鍵の生成時間に大きなばらつきがあり、さらにmlkemと比べてかなり遅いというのがグラフから読み取れる。
またml-kemは仕様上、rsaよりも鍵サイズが大きくなってしまう。
<img width="1210" height="751" alt="スクリーンショット 2026-02-06 9 39 38" src="https://github.com/user-attachments/assets/18efd7a4-4f32-4efb-8056-d37d844957af" />

## 9. 考察
調査した結果からmlkemは既存の暗号化技術にくれべてやはり耐量子に優れており明確なメリットがる一方、まだ国のプランが決まっておらず、情報をキャッチアップが求められると感じた。

## 10. 参考文献
[https://it-trend.jp/encryption/article/64-0063](https://it-trend.jp/encryption/article/64-0063)
https://www.nri-secure.co.jp/blog/pqc1
