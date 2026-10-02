--[[
=============================================================================
  Kamailio SMS-IWF & SMPP Module - Production Lua KEMI Script (app.lua)
=============================================================================
  Bu dosya, Kamailio KEMI (Kamailio Embedded Interface) mimarisi ile
  Lua scripting dilinde calisan gelismis SMS routing, manipulation ve
  coklu SMPP baglanti yonetimini icerir.
=============================================================================
--]]

-- KEMI Routing Entrypoint
function ksr_request_route()
    KSR.info("===== Lua KSR Request Route tetiklendi: " .. KSR.pv.get("$rm") .. " =====\n")

    -- 1. Max-Forwards kontrolu
    if KSR.maxfwd.process_maxfwd(10) < 0 then
        KSR.sl.send_reply(483, "Too Many Hops")
        return
    end

    -- 2. SIP MESSAGE ve IMS VoLTE SMS Yakalama
    if KSR.is_MESSAGE() then
        ksr_route_sms_iwf()
        return
    end

    -- Standart SIP cagrilari icin yanit
    KSR.sl.send_reply(404, "Not Found")
end

-- SMS Interworking Function (SMS-IWF) Lua Yonlendirme Motoru
function ksr_route_sms_iwf()
    local src_user = KSR.pv.get("$fU") or "ANONYMOUS"
    local dst_user = KSR.pv.get("$rU") or ""
    local body     = KSR.pv.get("$rb") or ""
    local ctype    = KSR.pv.get("$hdr(Content-Type)") or ""

    KSR.info(string.format("[SMS-IWF LUA] Mesaj Alindi: Kimden=%s -> Kime=%s (Type=%s)\n", src_user, dst_user, ctype))

    -- A. 3GPP IMS VoLTE / VoWiFi SMS Kontrolu (RP-DATA binary)
    if string.find(ctype, "application/vnd.3gpp.sms") then
        KSR.info("[SMS-IWF LUA] 3GPP IMS VoLTE Encapsulated SMS tespit edildi!\n")
        -- SMSC Secimi ve Gonderim (IP-SM-GW)
        KSR.smpp.send("sim1", src_user, dst_user, body)
        KSR.sl.send_reply(200, "IMS SMS Accepted by Kamailio SMS-IWF")
        return
    end

    -- B. Numara ve Prefix Bazli Akilli Operatör Routing (LCR)
    local target_smsc = "sim1" -- Varsayilan sim1

    if string.sub(dst_user, 1, 4) == "9053" then
        -- Turkcell Numaralari (90530..90539)
        target_smsc = "sim1"
        KSR.info("[SMS-IWF LUA] Hedef Turkcell: 'sim1' operatorune yonlendiriliyor.\n")
    elseif string.sub(dst_user, 1, 4) == "9054" then
        -- Vodafone Numaralari (90540..90549)
        target_smsc = "sim2"
        KSR.info("[SMS-IWF LUA] Hedef Vodafone: 'sim2' operatorune yonlendiriliyor.\n")
    elseif string.sub(dst_user, 1, 4) == "9055" or string.sub(dst_user, 1, 4) == "9050" then
        -- Turk Telekom Numaralari (90550..90559, 90505..90507)
        target_smsc = "sim3"
        KSR.info("[SMS-IWF LUA] Hedef Turk Telekom: 'sim3' operatorune yonlendiriliyor.\n")
    else
        -- Uluslararasi / Diger Numaralar (Global Trunk)
        target_smsc = "sim4"
        KSR.info("[SMS-IWF LUA] Hedef Uluslararasi/Diger: 'sim4' trunk'ina yonlendiriliyor.\n")
    end

    -- C. SMS Mesajini Ilgili SMPP Sunucusuna Ilet
    local rc = KSR.smpp.send(target_smsc, src_user, dst_user, body)
    if rc == 1 then
        KSR.info(string.format("[SMS-IWF LUA] SMS basariyla '%s' sunucusuna iletildi.\n", target_smsc))
        KSR.sl.send_reply(200, "SMS Queued & Sent to SMSC")
    else
        KSR.err(string.format("[SMS-IWF LUA] SMS gonderimi basarisiz! (Target=%s)\n", target_smsc))
        KSR.sl.send_reply(500, "SMS Delivery Failed")
    end
end
