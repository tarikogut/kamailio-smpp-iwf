# Kamailio SMS-IWF & Carrier-Grade SMPP Module
### Native SMS Interworking Function (SMS-IWF) & IP-SM-GW for Kamailio SIP Server

[![License](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Kamailio](https://img.shields.io/badge/Kamailio-v5.x%20%2F%20v6.x-orange.svg)](https://www.kamailio.org)
[![SMPP](https://img.shields.io/badge/SMPP-v3.4%20%2F%20v5.0-green.svg)](https://smpp.org)
[![Tests](https://img.shields.io/badge/Tests-69%2F69%20Passing-brightgreen.svg)](test_smpp.c)

---

## 🇹🇷 Türkçe Dokümantasyon

### 1. Genel Bakış
**Kamailio SMS-IWF**, telekom operatörleri, SMS toplayıcıları (aggregators) ve kurumsal haberleşme platformları için geliştirilmiş yerel (native C) bir Kamailio modülüdür. Kamailio'yu 3. parti harici SMS gateway'lere (Kannel, Jasmin vb.) ihtiyaç duymadan doğrudan **Carrier-Grade SMSC Sunucusu, ESME İstemcisi ve IMS VoLTE IP-SM-GW (3GPP TS 23.204)** haline getirir.

### 2. Temel Yetenekler
- **SMPP v3.4 & v5.0 Desteği:** Transmitter, Receiver ve tam çift yönlü Transceiver (TRX) oturumları.
- **3GPP TS 23.038 NLI (Ulusal Dil Tanımlayıcı):** Türkçe dahil şartnamedeki tüm 13 dilin Single Shift (Ek A.2.1) ve Locking Shift (Ek A.3.1) tablolarını destekler. Türkçe karakterler GSM 7-bit korunur (tek SMS'te 155 karaktere kadar UCS-2 maliyetine düşmeden iletilir).
- **BTK B-Kodu Enjeksiyonu ve Segment Koruması:** Mesaj sonuna otomatik operatör kodu (örn. ` B251`, ` B001`) eklenirken mesajın 160 GSM / 70 UCS-2 sınırını aşıp faturada 2 SMS'e katlanmasını engelleyen koruma motoru.
- **Birleşik DLR Normalizasyon & Onarım Motoru (Unified DLR Healing):** Standart dışı operatörlerin gönderdiği (gövdesi boş, yalnızca `0x001E`, `0x0427`, `0x0423` TLV parametreleri içeren) DLR raporlarını otomatik yakalar, normalize eder ve alt istemcilere standart Appendix B DLR gövdesi (`id:... stat:DELIVRD err:000`) olarak dönüştürür.
- **Özelleştirilebilir Mesaj ID (Custom MsgID Pattern):** Müşteri hesabı bazlı veya genel şablon motoru (`%PREFIX%`, `%ACCOUNT%`, `%TIMESTAMP%`, `%HEXSEQ%`, `%DECSEQ%`).
- **Token Bucket MPS Hız Sınırlaması (Rate Limiting):** Her müşteri için saniye başına mesaj sınırı (MPS) enforce edilir, sınır aşıldığında anında `ESME_RTHROTTLED` (0x58) döner.
- **Kara Liste & Sahtecilik Filtresi (Anti-Fraud):** Regex ve anahtar kelime eşleşmesi ile zararlı/kumar mesajları anında `ESME_RMSGBLOCKED` (0x67) ile reddedilir.
- **Sıfır Kesintiyle Canlı Güncelleme:** `kamcmd smpp.reload` ile oturumları koparmadan bellek içi hesaplar, operatörler ve kara listeler anında güncellenir.

### 3. Hızlı Kurulum & Çalıştırma (Docker)

```bash
# 1. Depoyu klonlayın
git clone https://github.com/tarikogut/kamailio-smpp-iwf.git
cd kamailio-smpp-iwf

# 2. Docker imajını derleyin
docker build -f docker/Dockerfile -t kamailio-smpp-iwf .

# 3. Kamailio SMS-IWF konteynerini başlatın
docker run -d --name kamailio_iwf \
  -p 2779:2779 \
  -p 5060:5060/udp \
  -p 5060:5060/tcp \
  -v $(pwd)/examples/kamailio_smpp_iwf.cfg:/usr/local/etc/kamailio/kamailio.cfg \
  kamailio-smpp-iwf /usr/local/sbin/kamailio -DD -E -f /usr/local/etc/kamailio/kamailio.cfg
```

### 4. İstemci Testi
Kamailio SMS-IWF varsayılan olarak `2779` portunda dinler:
```bash
python3 examples/test_client.py
```
**Bağlantı Bilgileri:**
- **Host:** `127.0.0.1`
- **Port:** `2779`
- **System ID:** `kamailio_client`
- **Password:** `kamailio_pass`
- **SMPP Versiyonu:** `v3.4` (0x34)

---

## 🇬🇧 English Documentation

### 1. Overview
**Kamailio SMS-IWF** is a native, carrier-grade Kamailio module providing an all-in-one **SMS Interworking Function (SMS-IWF)**, **Dual-Mode SMPP Server/Client Engine (v3.4 & v5.0)**, and **3GPP IMS VoLTE/VoWiFi IP-SM-GW (3GPP TS 23.204 / TS 24.341)**.

It eliminates the need for middleman SMS gateways (such as Kannel or Jasmin), routing SMS traffic natively with line-rate performance and sub-millisecond latency.

### 2. Key Features
- **SMPP v3.4 & v5.0 Compliance:** Native support for TX, RX, and full-duplex TRX sessions.
- **3GPP TS 23.038 NLI Engine:** Supports all 13 National Language Identifiers with Single Shift (Annex A.2.1) and Locking Shift (Annex A.3.1). Transliterates or preserves 7-bit packing to avoid UCS-2 cost penalties.
- **Regulatory BTK B-Code Injection:** Suffix/prefix insertion with segment boundary safety (prevents unexpected multi-part billing charges).
- **Unified DLR Normalization & Auto-Healing Engine:** Resolves vendor non-standard delivery receipts (empty `short_message` with TLVs: `receipted_message_id` `0x001E`, `message_state` `0x0427`, `network_error_code` `0x0423`) and reconstructs standard Appendix B DLR bodies transparently.
- **Account-Based Message ID Template Customization:** Flexible pattern engine (`%PREFIX%-%TIMESTAMP%-%HEXSEQ%` or per-account patterns).
- **In-Memory Token Bucket MPS Rate Limiter:** Per-account strict throttling with instant `ESME_RTHROTTLED` (`0x58`) and v5.0 `congestion_state` TLV feedback.
- **Anti-Fraud & Regex Blacklist Engine:** Drops or rejects spam/phishing with `ESME_RMSGBLOCKED` (`0x67`).
- **Zero-Downtime Hot Reloading:** Live configuration reload without dropping active TCP binds via `kamcmd smpp.reload`.

### 3. Architecture

```
+-----------------------------------------------------------------------------------------+
|                         KAMAILIO SMS-IWF (INTERWORKING FUNCTION)                        |
|                                                                                         |
|       +-------------------------------------------------------------------------+       |
|       |                     Multi-Protocol Translation Matrix                   |       |
|       +-------------------------------------------------------------------------+       |
|               ^                      ^                      ^             ^             |
|               |                      |                      |             |             |
|               v                      v                      v             v             |
|     [ SMPP v3.4 / v5.0 ]    [ 3GPP IMS VoLTE/5G ]     [ HTTP / REST ] [ SIP MESSAGE ]   |
|        (ESME & SMSC)       (3GPP TS 23.204 IP-SM-GW)   (CPaaS / Web)    (RFC 3428)      |
|               |                      |                      |             |             |
+---------------+----------------------+----------------------+-------------+-------------+
```

### 4. Configuration Reference (`kamailio.cfg`)

```kamailio
loadmodule "smpp.so"

modparam("smpp", "listen_ip", "0.0.0.0")
modparam("smpp", "listen_port", 2779)
modparam("smpp", "default_client_mps", 50)
modparam("smpp", "enquire_link_interval", 30)
modparam("smpp", "msgid_format", "%PREFIX%-%TIMESTAMP%-%HEXSEQ%")

request_route {
    if (is_method("MESSAGE")) {
        # Bridge SIP MESSAGE to SMPP SMSC
        smpp_send("sim1", "$fU", "$rU", "$rb");
        sl_send_reply("200", "SMS Accepted by SMS-IWF");
        exit;
    }
}
```

### 5. Running the Unit & Verification Test Suite

```bash
clang -Wall -Wextra -O2 \
  smpp_tlv.c smpp_pdu.c smpp_nli.c smpp_manip.c \
  smpp_ratelimit.c smpp_config.c smpp_client.c \
  smpp_server.c smpp_interwork.c smpp_dlr.c \
  test_smpp.c -o test_smpp && ./test_smpp
```
Result: **11 Test Suites, 69 Tests Passed, 0 Failures.**

---

### License
GPL-2.0-or-later (Kamailio Module License). Developed for carrier-grade telecom deployments.
