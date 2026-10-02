# Kamailio SMS-IWF & Carrier-Grade SMPP Module
### Native SMS Interworking Function (SMS-IWF) & IP-SM-GW for Kamailio SIP Server

[![License](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Kamailio](https://img.shields.io/badge/Kamailio-v5.x%20%2F%20v6.x-orange.svg)](https://www.kamailio.org)
[![SMPP](https://img.shields.io/badge/SMPP-v3.4%20%2F%20v5.0-green.svg)](https://smpp.org)
[![Tests](https://img.shields.io/badge/Tests-98%2F98%20Passing-brightgreen.svg)](test_smpp.c)

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
- **ENUM & MNP (Numara Taşınabilirliği) Motoru:** RFC 3761 `e164.arpa` DNS ENUM, yerel yüksek hızlı bellek içi hash tablosu veya Redis dip sorgusu ile taşınmış numaraları tespit eder. Numaranın güncel operatörünü (Routing Number / RN) bularak SMS'i doğrudan doğru operatör trunk'ına (`sim1`, `sim2`, `sim3`) yönlendirir.
- **Yerleşik REST API Sunucusu (Management, Send, DLR Query):** Port 8080 üzerinde çalışan dahili HTTP/1.1 REST API sunucusu. Bearer Token korumalıdır. Sistem durumu izleme, konfigürasyonu canlı yenileme (`/api/v1/reload`), doğrudan HTTP üzerinden SMS gönderme (`POST /api/v1/sms/send`) ve DLR teslim raporu sorgulama (`GET /api/v1/sms/query?id=...`) yetenekleri sunar.
- **Sıfır Kesintiyle Canlı Güncelleme:** `kamcmd smpp.reload` veya HTTP `POST /api/v1/reload` ile oturumları koparmadan bellek içi hesaplar, operatörler ve kara listeler anında güncellenir.

### 3. Dahili REST API (Yönetim, SMS Gönderme ve Rapor Sorgulama)

Kamailio SMPP modülü, üçüncü parti web servisleri ve mikroservislerle hızlı entegrasyon için dahili HTTP REST API sunucusu barındırır:

#### REST API Endpoint'leri:
- `GET /api/v1/health` - Genel sistem sağlık kontrolü (Public, Token gerektirmez).
- `GET /api/v1/status` - Anlık SMS-IWF durum özeti ve istatistikler.
- `POST /api/v1/reload` - Aktif oturumları kesmeden anında konfigürasyon yenileme.
- `POST /api/v1/sms/send` - HTTP JSON ile anında SMS dispatch etme.
- `GET /api/v1/sms/query?id=<message_id>` - Gerçek zamanlı teslim raporu (DLR) sorgulama.

#### REST API Örnek Kullanımları (`curl`):

```bash
# 1. Sağlık Kontrolü
curl -i http://127.0.0.1:8080/api/v1/health

# 2. Sistem Durumu ve İstatistikler
curl -i http://127.0.0.1:8080/api/v1/status \
  -H "Authorization: Bearer secret-token-123"

# 3. Sıfır Kesintiyle Canlı Konfigürasyon Yenileme (Hot-Reload)
curl -i -X POST http://127.0.0.1:8080/api/v1/reload \
  -H "Authorization: Bearer secret-token-123"

# 4. HTTP Üzerinden SMS Gönderme (SMS Dispatch)
curl -i -X POST http://127.0.0.1:8080/api/v1/sms/send \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "smsc_id": "sim1",
    "from": "KAMAILIO",
    "to": "905321234567",
    "text": "Merhaba! Kamailio SMS-IWF REST API testi."
  }'

# 5. DLR / Teslimat Raporu Sorgulama
curl -i "http://127.0.0.1:8080/api/v1/sms/query?id=REST-20261002070000-03E9" \
  -H "Authorization: Bearer secret-token-123"
```

### 4. Hızlı Kurulum & Çalıştırma (Docker)

```bash
# 1. Depoyu klonlayın
git clone https://github.com/tarikogut/kamailio-smpp-iwf.git
cd kamailio-smpp-iwf

# 2. Docker imajını derleyin
docker build -f docker/Dockerfile -t kamailio-smpp-iwf .

# 3. Kamailio SMS-IWF konteynerini başlatın
docker run -d --name kamailio_iwf \
  -p 2779:2779 \
  -p 8080:8080 \
  -p 5060:5060/udp \
  -p 5060:5060/tcp \
  -v $(pwd)/examples/kamailio_smpp_iwf.cfg:/usr/local/etc/kamailio/kamailio.cfg \
  kamailio-smpp-iwf /usr/local/sbin/kamailio -DD -E -f /usr/local/etc/kamailio/kamailio.cfg
```

### 5. Çoklu SMPP Sunucu & İstemci Bind Mimarisi (Multi-Bind)
**Soru: Birden fazla SMPP sunucusuna aynı anda bağlanabilir ve birden fazla istemci bind kabul edebilir mi?**
**Cevap: Evet, kesinlikle! Mimarimiz tam bir havuz (connection pool) şeklinde çalışır:**
1. **Çoklu Outbound SMSC Bağlantısı (ESME Mode):** Kamailio aynı anda onlarca farklı operatöre (Turkcell, Vodafone, TT, yurtdışı SMSC'ler) paralel `transceiver (TRX)` olarak bağlanabilir. Her bağlantı bağımsız soket ve oturum durum makinesi (`smpp_client_conn_t`) ile yönetilir.
2. **Çoklu Inbound İstemci Bağlantısı (SMSC Server Mode):** Dışarıdan bağlanan onlarca müşteri veya uygulama (ESME) aynı anda Kamailio'ya `bind_transceiver` yapabilir (`max_binds` limitiyle korunur).

### 6. Lua Scripting (KEMI) ile Akıllı Yönlendirme
Kamailio'nun yerel **Lua KEMI (`app_lua`)** motoru ile karmaşık telekom yönlendirmelerini doğrudan Lua fonksiyonlarıyla yapabilirsiniz:

```lua
-- examples/app.lua
function ksr_request_route()
    if KSR.is_MESSAGE() then
        local dst = KSR.pv.get("$rU")
        local src = KSR.pv.get("$fU")
        local body = KSR.pv.get("$rb")

        -- Numara Prefixine Göre Operatör Dağıtımı (LCR)
        if string.sub(dst, 1, 4) == "9053" then
            KSR.smpp.send("turkcell_smsc", src, dst, body)
        elseif string.sub(dst, 1, 4) == "9054" then
            KSR.smpp.send("vodafone_smsc", src, dst, body)
        else
            KSR.smpp.send("global_smsc", src, dst, body)
        end
        KSR.sl.send_reply(200, "SMS Accepted")
    end
end
```

### 7. İstemci Testi
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
- **ENUM & MNP (Mobile Number Portability) Engine:** Supports RFC 3761 `e164.arpa` DNS ENUM, high-speed in-memory hash tables, or Redis database dips to identify ported numbers. Dynamically queries the recipient's Routing Number (RN) and routes SMS to the destination carrier (`sim1`, `sim2`, `sim3`) with optimal LCR cost.
- **Built-in REST API Server (Management, Send & DLR Query):** Micro HTTP/1.1 REST API server on port 8080. Protected by Bearer token authorization. Provides live health check, system status overview, zero-downtime hot reloading (`POST /api/v1/reload`), SMS dispatch (`POST /api/v1/sms/send`), and real-time delivery receipt querying (`GET /api/v1/sms/query?id=...`).
- **Zero-Downtime Hot Reloading:** Live configuration reload without dropping active TCP binds via `kamcmd smpp.reload` or HTTP `POST /api/v1/reload`.

### 3. Built-in REST API (Management, SMS Dispatch, DLR Query)

Kamailio SMPP includes an embedded HTTP REST API engine for seamless integration with microservices and external CPaaS applications:

#### Available Endpoints:
- `GET /api/v1/health` - Liveness & health check (Public).
- `GET /api/v1/status` - Live SMS-IWF statistics and configuration overview.
- `POST /api/v1/reload` - Zero-downtime hot reload without dropping active SMPP binds.
- `POST /api/v1/sms/send` - Send SMS via HTTP JSON.
- `GET /api/v1/sms/query?id=<message_id>` - Real-time DLR and message state query.

#### Quick `curl` Examples:

```bash
# 1. Health Check
curl -i http://127.0.0.1:8080/api/v1/health

# 2. System Status Overview
curl -i http://127.0.0.1:8080/api/v1/status \
  -H "Authorization: Bearer secret-token-123"

# 3. Hot Configuration Reload
curl -i -X POST http://127.0.0.1:8080/api/v1/reload \
  -H "Authorization: Bearer secret-token-123"

# 4. Dispatch SMS via REST API
curl -i -X POST http://127.0.0.1:8080/api/v1/sms/send \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "smsc_id": "sim1",
    "from": "KAMAILIO",
    "to": "905321234567",
    "text": "Hello from Kamailio SMS-IWF REST API!"
  }'

# 5. Query Delivery Status (DLR)
curl -i "http://127.0.0.1:8080/api/v1/sms/query?id=REST-20261002070000-03E9" \
  -H "Authorization: Bearer secret-token-123"
```

### 4. Architecture

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

### 5. Multi-Bind & Connection Pooling Architecture
**Can Kamailio bind to multiple SMPP SMSCs simultaneously and accept multiple inbound client binds?**
**Yes, absolutely.** The module is engineered with a carrier-grade multi-session pooling architecture:
- **Multi-SMSC Outbound Pooling (ESME Mode):** Kamailio can establish parallel `bind_transceiver` sessions to multiple upstream carriers (e.g. `sim1`, `sim2`, `sim3`, `sim4`). Each carrier connection maintains its own independent socket, sequence counter, keepalive timer, and state machine (`smpp_client_conn_t`).
- **Concurrent Inbound Client Binds (SMSC Server Mode):** Multiple distinct ESME clients or concurrent binds from the same account can connect simultaneously to Kamailio's listener port (governed by the `max_binds` configuration per account).

### 6. Lua KEMI Scripting Integration
With Kamailio KEMI (`app_lua`), you can write SMS routing, Least Cost Routing (LCR), and protocol translation logic natively in Lua:

```lua
-- examples/app.lua
function ksr_request_route()
    if KSR.is_MESSAGE() then
        local src = KSR.pv.get("$fU")
        local dst = KSR.pv.get("$rU")
        local body = KSR.pv.get("$rb")

        -- Prefix-based LCR Routing across multiple SMPP SMSC connections
        if string.sub(dst, 1, 4) == "9053" then
            KSR.smpp.send("sim1", src, dst, body) -- Turkcell Carrier
        elseif string.sub(dst, 1, 4) == "9054" then
            KSR.smpp.send("sim2", src, dst, body) -- Vodafone Carrier
        else
            KSR.smpp.send("sim3", src, dst, body) -- Global Carrier
        end
        KSR.sl.send_reply(200, "SMS Accepted by KEMI")
    end
end
```

### 7. Configuration Reference (`kamailio.cfg`)

```kamailio
loadmodule "smpp.so"

modparam("smpp", "listen_ip", "0.0.0.0")
modparam("smpp", "listen_port", 2779)
modparam("smpp", "default_client_mps", 50)
modparam("smpp", "enquire_link_interval", 30)
modparam("smpp", "msgid_format", "%PREFIX%-%TIMESTAMP%-%HEXSEQ%")
modparam("smpp", "http_api_enable", 1)
modparam("smpp", "http_api_port", 8080)
modparam("smpp", "http_api_token", "secret-token-123")

request_route {
    if (is_method("MESSAGE")) {
        # Bridge SIP MESSAGE to SMPP SMSC
        smpp_send("sim1", "$fU", "$rU", "$rb");
        sl_send_reply("200", "SMS Accepted by SMS-IWF");
        exit;
    }
}
```

### 8. Running the Unit & Verification Test Suite

```bash
clang -Wall -Wextra -O2 \
  smpp_tlv.c smpp_pdu.c smpp_nli.c smpp_manip.c \
  smpp_ratelimit.c smpp_config.c smpp_client.c \
  smpp_server.c smpp_interwork.c smpp_dlr.c smpp_mnp.c smpp_http_api.c \
  test_smpp.c -o test_smpp && ./test_smpp
```
Result: **13 Test Suites, 98 Tests Passed, 0 Failures.**


---

### License
GPL-2.0-or-later (Kamailio Module License). Developed for carrier-grade telecom deployments.
