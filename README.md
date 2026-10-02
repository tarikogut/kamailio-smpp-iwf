# Kamailio SMS-IWF & Carrier-Grade SMPP Module
### Native SMS Interworking Function (SMS-IWF) & IP-SM-GW for Kamailio SIP Server

[![License](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Kamailio](https://img.shields.io/badge/Kamailio-v5.x%20%2F%20v6.x-orange.svg)](https://www.kamailio.org)
[![SMPP](https://img.shields.io/badge/SMPP-v3.4%20%2F%20v5.0-green.svg)](https://smpp.org)
[![Tests](https://img.shields.io/badge/Tests-113%2F113%20Passing-brightgreen.svg)](test_smpp.c)

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
- **Tam Kapsamlı REST API (Yönetim, Bağlantı & Kullanıcı CRUD, SMS, DLR):** Port 8080 üzerinde çalışan dahili HTTP/1.1 REST API sunucusu. Bearer Token korumalıdır. Sistem durumu izleme, konfigürasyonu canlı yenileme (`/api/v1/reload`), SMSC bağlantılarını dinamik yönetme (listeleme, ekleme, silme, start/stop), ESME kullanıcılarını yönetme (listeleme, ekleme, silme), doğrudan HTTP üzerinden SMS gönderme (`POST /api/v1/sms/send`) ve DLR teslim raporu sorgulama (`GET /api/v1/sms/query?id=...`) yetenekleri sunar.
- **Sıfır Kesintiyle Canlı Güncelleme:** `kamcmd smpp.reload` veya HTTP `POST /api/v1/reload` ile oturumları koparmadan bellek içi hesaplar, operatörler ve kara listeler anında güncellenir.

### 3. Konfigürasyon Parametreleri (`kamailio.cfg`)

Kamailio SMPP modülü `modparam("smpp", "parametre_adi", deger)` sözdizimi ile yapılandırılır:

| Parametre Adı | Veri Tipi | Varsayılan | Açıklama |
| :--- | :--- | :--- | :--- |
| `listen_ip` | `string` | `"0.0.0.0"` | SMPP SMSC sunucusunun dinleyeceği yerel IP adresi. |
| `listen_port` | `int` | `2775` | SMPP dinleme portu (Örn. `2779`). |
| `worker_procs` | `int` | `2` | SMPP PDU işleme süreç / thread sayısı. |
| `enquire_link_interval` | `int` | `30` | Otomatik SMPP keepalive (ping/pong) periyodu (saniye). |
| `response_timeout` | `int` | `5` | SMSC yanıt bekleme zaman aşımı (saniye). |
| `reconnect_interval` | `int` | `10` | Bağlantı koptuğunda yeniden bağlanma deneme aralığı. |
| `default_client_mps` | `int` | `30` | Tanımsız istemciler için varsayılan saniye başına mesaj limiti (MPS). |
| `msgid_format` | `string` | `"%PREFIX%-%TIMESTAMP%-%HEXSEQ%"` | Genel Mesaj ID şablon formatı (`%PREFIX%`, `%ACCOUNT%`, `%TIMESTAMP%`, `%HEXSEQ%`, `%DECSEQ%`). |
| `mnp_mode` | `int` | `0` | Numara taşınabilirliği modu: `0`=Kapalı, `1`=DNS ENUM, `2`=Memory Hash, `3`=Redis Dip. |
| `enum_suffix` | `string` | `"e164.arpa"` | ENUM DNS sorguları için kök alan adı. |
| `mnp_redis_host` | `string` | `"127.0.0.1"` | MNP sorguları için Redis sunucu adresi. |
| `mnp_cache_ttl` | `int` | `3600` | MNP sonuçları için bellek içi önbellek süresi (saniye). |
| `http_api_enable` | `int` | `1` | Dahili HTTP REST API sunucusunu etkinleştirir (`1`) veya kapatır (`0`). |
| `http_api_port` | `int` | `8080` | REST API dinleme portu. |
| `http_api_token` | `string` | `"secret-token-123"` | **Tüm korumalı REST API endpoint'leri için zorunlu Bearer Token.** |

---

### 4. Dahili REST API (Yönetim, Bağlantı & Kullanıcı CRUD, SMS ve Rapor)

Kamailio SMPP modülü, web panelleri ve mikroservislerle entegrasyon için tam teşekküllü CRUD REST API sunar:

#### REST API Endpoint Matrisi:
| Metot | Endpoint | Yetki | Açıklama |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Public | Liveness ve sistem sağlık kontrolü. |
| `GET` | `/api/v1/status` | Bearer Token | Anlık SMS-IWF istatistikleri ve durum özeti. |
| `POST` | `/api/v1/reload` | Bearer Token | Sıfır kesintiyle canlı konfigürasyon yenileme. |
| `POST` | `/api/v1/sms/send` | Bearer Token | HTTP JSON ile anında SMS dispatch etme. |
| `GET` | `/api/v1/sms/query?id=...`| Bearer Token | Gerçek zamanlı DLR / teslimat raporu sorgulama. |
| `GET` | `/api/v1/connections` | Bearer Token | Tüm outbound SMSC bağlantılarını ve durumlarını listeleme. |
| `POST` | `/api/v1/connections` | Bearer Token | Canlı yeni outbound SMSC bağlantısı ekleme & bind etme. |
| `DELETE` | `/api/v1/connections?id=...`| Bearer Token | Aktif SMSC bağlantısını koparma ve silme. |
| `POST` | `/api/v1/connections/start?id=...`| Bearer Token | Belirli bir SMSC bağlantısını canlı başlatma (TRX Bind). |
| `POST` | `/api/v1/connections/stop?id=...`| Bearer Token | Belirli bir SMSC bağlantısını durdurma (Unbind). |
| `GET` | `/api/v1/users` | Bearer Token | Tanımlı tüm inbound ESME istemci hesaplarını listeleme. |
| `POST` | `/api/v1/users` | Bearer Token | Yeni ESME kullanıcısı ekleme veya güncelleme. |
| `DELETE` | `/api/v1/users?id=...` | Bearer Token | ESME kullanıcısını silme. |

#### REST API Operasyonel Kullanım Örnekleri (`curl`):

```bash
# 1. Sağlık Kontrolü (Public)
curl -i http://127.0.0.1:8080/api/v1/health

# 2. Sistem Durumu ve Metrikler
curl -i http://127.0.0.1:8080/api/v1/status \
  -H "Authorization: Bearer secret-token-123"

# 3. Canlı Yeni Operatör/SMSC Bağlantısı Ekleme (POST)
curl -i -X POST http://127.0.0.1:8080/api/v1/connections \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "smsc_id": "turkcell_new",
    "host": "192.168.1.50",
    "port": 2775,
    "system_id": "kamailio_gw",
    "password": "operator_password",
    "default_b_code": "B251"
  }'

# 4. Operatör Bağlantısını Durdurma (Stop / Unbind)
curl -i -X POST "http://127.0.0.1:8080/api/v1/connections/stop?id=turkcell_new" \
  -H "Authorization: Bearer secret-token-123"

# 5. Operatör Bağlantısını Başlatma (Start / Bind)
curl -i -X POST "http://127.0.0.1:8080/api/v1/connections/start?id=turkcell_new" \
  -H "Authorization: Bearer secret-token-123"

# 6. Operatör Bağlantısını Silme (DELETE)
curl -i -X DELETE "http://127.0.0.1:8080/api/v1/connections?id=turkcell_new" \
  -H "Authorization: Bearer secret-token-123"

# 7. Yeni ESME Müşteri Hesabı Ekleme (POST User)
curl -i -X POST http://127.0.0.1:8080/api/v1/users \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "bank_client",
    "password": "bank_secure_password",
    "mps_limit": 150,
    "burst_limit": 300,
    "msgid_format": "BANK-%TIMESTAMP%-%HEXSEQ%"
  }'

# 8. Tanımlı ESME Hesaplarını Listeleme (GET Users)
curl -i http://127.0.0.1:8080/api/v1/users \
  -H "Authorization: Bearer secret-token-123"

# 9. ESME Hesabı Silme (DELETE User)
curl -i -X DELETE "http://127.0.0.1:8080/api/v1/users?id=bank_client" \
  -H "Authorization: Bearer secret-token-123"

# 10. HTTP Üzerinden SMS Gönderme
curl -i -X POST http://127.0.0.1:8080/api/v1/sms/send \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "smsc_id": "sim1",
    "from": "KAMAILIO",
    "to": "905321000000",
    "text": "Merhaba! Kamailio SMS-IWF REST API testi."
  }'

# 11. DLR / Teslimat Raporu Sorgulama
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

### 7. İstemci & Uçtan Uca Çoklu Protokol Testleri

#### A. SMPP İstemci ile SMS Gönderme ve Anlık DLR Alma Testi
Kamailio SMS-IWF varsayılan olarak `2779` portunda dinler:
```bash
python3 examples/test_client.py 2779
```
**Akış:**
`ESME BIND (2779)` ➔ `SUBMIT_SM` ➔ `Kamailio SMS-IWF (sim1 / 2775)` ➔ `SUBMIT_SM_RESP (MsgID)` ➔ Operatör Teslimatı ➔ `DELIVER_SM (DLR, stat:DELIVRD)` ➔ `DELIVER_SM_RESP ACK`

#### B. SIP'ten SMPP'ye SMS Gönderme (SIP-to-SMPP Gateway)
Kamailio SIP UDP 5060 portuna `MESSAGE` gönderildiğinde mesaj operatör SMPP bağlantısına iletilir ve SIP istemcisine `200 OK` dönülür:
```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 5071))
s.settimeout(3.0)
msg = (
    'MESSAGE sip:905321112233@127.0.0.1:5060 SIP/2.0\r\n'
    'Via: SIP/2.0/UDP 127.0.0.1:5071;branch=z9hG4bK889qwe;rport\r\n'
    'Max-Forwards: 70\r\n'
    'From: <sip:905329998877@127.0.0.1:5071>;tag=991122\r\n'
    'To: <sip:905321112233@127.0.0.1:5060>\r\n'
    'Call-ID: sip-msg-01@127.0.0.1\r\n'
    'CSeq: 1 MESSAGE\r\n'
    'Content-Type: text/plain\r\n'
    'Content-Length: 26\r\n\r\n'
    'SIP to SMPP interwork test'
)
s.sendto(msg.encode('utf-8'), ('127.0.0.1', 5060))
data, addr = s.recvfrom(4096)
print(data.decode('utf-8'))
"
```
**Sonuç:** `SIP/2.0 200 OK (Forwarded to SMPP)`

#### C. HTTP REST API'den SMPP'ye SMS Gönderme ve DLR Takibi (HTTP-to-SMPP)
```bash
# 1. SMS Gönder (POST)
curl -X POST http://127.0.0.1:8080/api/v1/sms/send \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{"smsc":"sim1","src":"API_CLIENT","dst":"905321112233","text":"Test Mesaji"}'

# Dönen Yanıt: {"status":"accepted","message_id":"0be72574...","smsc":"sim1","to":"905321112233"}

# 2. Teslimat Raporunu Sorgula (GET)
curl "http://127.0.0.1:8080/api/v1/sms/query?id=0be72574..." \
  -H "Authorization: Bearer secret-token-123"

# Dönen Yanıt: {"message_id":"0be72574...","status":"DELIVRD","smsc":"sim1",...}
```

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
- **Carrier-Grade CRUD REST API Engine (Connections, Users, SMS, DLR):** Micro HTTP/1.1 REST API server running on port 8080. Protected by Bearer token authorization. Supports health check, live statistics, zero-downtime hot reloading (`POST /api/v1/reload`), dynamic SMSC connection lifecycle management (list, add, delete, start, stop), dynamic ESME user management (list, add, delete), HTTP-based SMS dispatch (`POST /api/v1/sms/send`), and real-time delivery receipt querying (`GET /api/v1/sms/query?id=...`).
- **Zero-Downtime Hot Reloading:** Live configuration reload without dropping active TCP binds via `kamcmd smpp.reload` or HTTP `POST /api/v1/reload`.

### 3. Module Configuration Parameters (`kamailio.cfg`)

The Kamailio SMPP module is configured using standard `modparam("smpp", "parameter_name", value)` directives:

| Parameter Name | Data Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `listen_ip` | `string` | `"0.0.0.0"` | Local IP address for the SMPP SMSC server to bind and listen on. |
| `listen_port` | `int` | `2775` | SMPP listener port (e.g., `2779`). |
| `worker_procs` | `int` | `2` | Number of SMPP PDU processing workers / worker threads. |
| `enquire_link_interval` | `int` | `30` | Automatic SMPP keepalive (ping/pong) heartbeat interval in seconds. |
| `response_timeout` | `int` | `5` | Upstream SMSC response timeout in seconds. |
| `reconnect_interval` | `int` | `10` | Automatic reconnect attempt backoff interval upon connection drop. |
| `default_client_mps` | `int` | `30` | Default Messages-Per-Second (MPS) limit for unmetered clients. |
| `msgid_format` | `string` | `"%PREFIX%-%TIMESTAMP%-%HEXSEQ%"` | Global Message ID template pattern (`%PREFIX%`, `%ACCOUNT%`, `%TIMESTAMP%`, `%HEXSEQ%`, `%DECSEQ%`). |
| `mnp_mode` | `int` | `0` | Number portability resolution engine: `0`=Off, `1`=DNS ENUM, `2`=Memory Hash, `3`=Redis Dip. |
| `enum_suffix` | `string` | `"e164.arpa"` | Root DNS domain for RFC 3761 ENUM lookups. |
| `mnp_redis_host` | `string` | `"127.0.0.1"` | Redis server address for MNP database dips. |
| `mnp_cache_ttl` | `int` | `3600` | In-memory cache TTL for MNP resolution results in seconds. |
| `http_api_enable` | `int` | `1` | Enables (`1`) or disables (`0`) the embedded HTTP REST API server. |
| `http_api_port` | `int` | `8080` | HTTP REST API listening port. |
| `http_api_token` | `string` | `"secret-token-123"` | **Mandatory Bearer Token required for all protected REST API endpoints.** |

---

### 4. Built-in REST API (Management, Connection & User CRUD, SMS Dispatch, DLR Query)

Kamailio SMPP provides an embedded, zero-overhead HTTP/1.1 REST API engine for seamless integration with modern web dashboards, CPaaS orchestrators, and microservices:

#### REST API Endpoint Matrix:
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Public | Liveness probe and service health check. |
| `GET` | `/api/v1/status` | Bearer Token | Live SMS-IWF operational metrics and configuration state. |
| `POST` | `/api/v1/reload` | Bearer Token | Zero-downtime hot reload without terminating active binds. |
| `POST` | `/api/v1/sms/send` | Bearer Token | Instant SMS dispatch via HTTP JSON payload. |
| `GET` | `/api/v1/sms/query?id=...`| Bearer Token | Real-time DLR and message delivery state inquiry. |
| `GET` | `/api/v1/connections` | Bearer Token | List all outbound SMSC carrier connections and link states. |
| `POST` | `/api/v1/connections` | Bearer Token | Dynamically add and bind a new outbound SMSC connection in runtime. |
| `DELETE` | `/api/v1/connections?id=...`| Bearer Token | Gracefully unbind and remove an outbound SMSC connection. |
| `POST` | `/api/v1/connections/start?id=...`| Bearer Token | Trigger manual start/bind for a specific SMSC connection. |
| `POST` | `/api/v1/connections/stop?id=...`| Bearer Token | Trigger manual stop/unbind for a specific SMSC connection. |
| `GET` | `/api/v1/users` | Bearer Token | List all configured inbound ESME client accounts. |
| `POST` | `/api/v1/users` | Bearer Token | Dynamically create or update an ESME client user account. |
| `DELETE` | `/api/v1/users?id=...` | Bearer Token | Remove an ESME client user account. |

#### Operational `curl` Examples:

```bash
# 1. Health Check (Public)
curl -i http://127.0.0.1:8080/api/v1/health

# 2. Operational Status & Metrics
curl -i http://127.0.0.1:8080/api/v1/status \
  -H "Authorization: Bearer secret-token-123"

# 3. Add Dynamic SMSC Carrier Connection (POST Connection)
curl -i -X POST http://127.0.0.1:8080/api/v1/connections \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "smsc_id": "carrier_fast",
    "host": "192.168.1.50",
    "port": 2775,
    "system_id": "kamailio_gw",
    "password": "carrier_password",
    "default_b_code": "B251"
  }'

# 4. Stop SMSC Carrier Connection (Stop / Unbind)
curl -i -X POST "http://127.0.0.1:8080/api/v1/connections/stop?id=carrier_fast" \
  -H "Authorization: Bearer secret-token-123"

# 5. Start SMSC Carrier Connection (Start / Bind)
curl -i -X POST "http://127.0.0.1:8080/api/v1/connections/start?id=carrier_fast" \
  -H "Authorization: Bearer secret-token-123"

# 6. Delete SMSC Carrier Connection (DELETE Connection)
curl -i -X DELETE "http://127.0.0.1:8080/api/v1/connections?id=carrier_fast" \
  -H "Authorization: Bearer secret-token-123"

# 7. Create New Inbound ESME User Account (POST User)
curl -i -X POST http://127.0.0.1:8080/api/v1/users \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "fintech_client",
    "password": "strong_auth_token",
    "mps_limit": 200,
    "burst_limit": 400,
    "msgid_format": "FIN-%TIMESTAMP%-%HEXSEQ%"
  }'

# 8. List Configured ESME Accounts (GET Users)
curl -i http://127.0.0.1:8080/api/v1/users \
  -H "Authorization: Bearer secret-token-123"

# 9. Delete ESME User Account (DELETE User)
curl -i -X DELETE "http://127.0.0.1:8080/api/v1/users?id=fintech_client" \
  -H "Authorization: Bearer secret-token-123"

# 10. Send SMS via HTTP JSON API
curl -i -X POST http://127.0.0.1:8080/api/v1/sms/send \
  -H "Authorization: Bearer secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{
    "smsc_id": "sim1",
    "from": "KAMAILIO",
    "to": "905321000000",
    "text": "Hello from Kamailio SMS-IWF REST API!"
  }'

# 11. Query Delivery Status (DLR)
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
modparam("smpp", "reconnect_interval", 10)
modparam("smpp", "msgid_format", "%PREFIX%-%TIMESTAMP%-%HEXSEQ%")
modparam("smpp", "http_api_enable", 1)
modparam("smpp", "http_api_port", 8080)
modparam("smpp", "http_api_token", "secret-token-123")

request_route {
    if (is_method("MESSAGE")) {
        # Bridge SIP MESSAGE to SMPP SMSC
        smpp_send("sim1", "$fU", "$rU", "$rb");
        sl_send_reply("200", "OK (Forwarded to SMPP)");
        exit;
    }
}
```

### 8. Running the Unit & Verification Test Suite

```bash
gcc -Wall -O2 test_smpp.c smpp_pdu.c smpp_tlv.c smpp_manip.c smpp_ratelimit.c \
  smpp_nli.c smpp_interwork.c smpp_dlr.c smpp_config.c smpp_client.c \
  smpp_server.c smpp_mnp.c smpp_http_api.c -lpthread -o test_smpp && ./test_smpp
```
Result: **13 Test Suites, 113 Tests Passed, 0 Failures.**


---

### License
GPL-2.0-or-later (Kamailio Module License). Developed for carrier-grade telecom deployments.
