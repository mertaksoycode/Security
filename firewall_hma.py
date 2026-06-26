from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import os
import requests
import pandas
import sys
from scapy.all import sniff, IP, TCP, UDP, Raw,send
import threading
import logging
import socket
import re
import urllib3
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
banner = """
    __  ____  ______
   / / / /  |/  /   |
  / /_/ / /|_/ / /| |
 / __  / /  / / ___ |
/_/ /_/_/  /_/_/  |_|


Mert Aksoy abinin Adamıyım >:)
"""
ip_sayaclari = {}
AI_MODEL = None
engellenen_ipler = set()
LOG_DOSYASI = "engellenenler.txt"
GERI_YANSIT_AKTIFMI = True
DDOS_PAKET_ESIGI = 980

GUVENILIR_HOSTLAR = [
     "google.com",
     "facebook.com",
     "epic",
     "epicgames",
     "steam",
     "instagram",
     "tiktok",
     "gemini",
     "microsoft",
     "youtube",
     "meta",
     "unity",
     "capcut",
     "outlook",
     "gmail"
     
]




urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def modeli_hazirla():
    global AI_MODEL, UYGULAMA_MODELI
    print("[*] Bilgileri alıyorum abi...")
    
    
    egitim_verisi = {
        'istek_sayisi': [
            10, 15, 20, 30, 25, 18, 22,       
            50, 100, 250, 500, 1000, 2500, 5000,
            20000, 50000, 100000                
        ],
        'paket_boyutu': [
            64, 128, 64, 512, 64, 128, 64,     
            1024, 1400, 1500, 1500, 1500, 1500, 1500, 
            1500, 1500, 1500                   
        ]
     }
    df = pandas.DataFrame(egitim_verisi)
    

    AI_MODEL = IsolationForest(contamination=0.11, random_state=42)
    AI_MODEL.fit(df)

    egitim_verisi_uygulama = {
         'hedef_port': [443, 80, 443, 22, 8080, 4444,139,23],
         'paket_boyutu':[1500,1200,1400,64,512,1500,1024,64],
         'trafik_turu':[0,0,0,0,0,1,1,1]
    }
    df_uygulama = pandas.DataFrame(egitim_verisi_uygulama)
    X_uyg = df_uygulama[['hedef_port', 'paket_boyutu']]
    y_uyg = df_uygulama['trafik_turu']

    UYGULAMA_MODELI = RandomForestClassifier(random_state=42)
    UYGULAMA_MODELI.fit(X_uyg,y_uyg)
    if os.path.exists(LOG_DOSYASI):
          print(f"[*] {LOG_DOSYASI} dosyası bulundu, eski engellenen IP'ler yüklenyor...")
          with open(LOG_DOSYASI, "r", encoding="utf-8") as f:
               for satir in f:
                    ip = satir.strip()
                    if ip:
                         engellenen_ipler.add(ip)
          print(f"[+] Toplam {len(engellenen_ipler)} adet eski IP hafızaya geri yüklendi.")
    else:
        print("[-] Geçmişe ait engellenen IP veri tabanı bulunamadı, sıfırdan başlanıyor.")
    print("[+] Herşeyi anladım abi hazır!")
def ip_bilgi_getir(ip_adresi):
     
     if ip_adresi.startswith("192.168.") or ip_adresi.startswith("10.") or ip_adresi.startswith("172.") or ip_adresi == "127.0.0.1":
          print(f"[YEREL AĞ TEHDİDİ] -> {ip_adresi} bir yerel ağ adresidir, coğrafi konum sorgusu atlanıyor.")
          
         
         
          return

     print(f"{ip_adresi} için dnschecker.org üzerinden coğrafi konum bilgileri sorgulanıyor...")
     try:
          url = f"https://dnschecker.org/ip-location.php?ip={ip_adresi}"
          headers = {
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
          }
          
          yanit = requests.get(url, headers=headers, timeout=5)

          if yanit.status_code == 200:
               html_icerik = yanit.text
               
               ulke_arama = re.search(r'<th>Country</th>\s*<td>(.*?)</td>', html_icerik, re.IGNORECASE)
               sehir_arama = re.search(r'<th>City</th>\s*<td>(.*?)</td>', html_icerik, re.IGNORECASE)
               isp_arama = re.search(r'<th>ISP</th>\s*<td>(.*?)</td>', html_icerik, re.IGNORECASE)
               koordinat_arama = re.search(r'<th>Latitude / Longitude</th>\s*<td>(.*?)</td>', html_icerik, re.IGNORECASE)
               
               ulke_sonuc = ulke_arama.group(1).strip() if ulke_arama else "Bilinmiyor"
               sehir_sonuc = sehir_arama.group(1).strip() if sehir_arama else "Bilinmiyor"
               isp_sonuc = isp_arama.group(1).strip() if isp_arama else "Bilinmiyor"
               koordinat_sonuc = koordinat_arama.group(1).strip() if koordinat_arama else "Bilinmiyor"
               
               ulke_sonuc = re.sub(r'<[^>]*>', '', ulke_sonuc)
               sehir_sonuc = re.sub(r'<[^>]*>', '', sehir_sonuc)
               isp_sonuc = re.sub(r'<[^>]*>', '', isp_sonuc)

               print("-" * 50)
               print(f"  [TEHDİT COĞRAFİ KONUMU - DNSCHECKER]")
               print(f"    Ülke: {ulke_sonuc}")
               print(f"    Şehir: {sehir_sonuc}")
               print(f"    İnternet Sağlayıcı (ISP): {isp_sonuc}")
               print(f"    Koordinat (Lat/Lon): {koordinat_sonuc}")
               print("-" * 50)          

              
               return
          else:
               print(f"[-] Dnschecker sitesinden olumsuz yanıt alındı. Durum Kodu: {yanit.status_code}")
     except Exception as e:
          print(f"[!] Dnschecker sorgusu sırasında bir ağ hatası oluştu (Konum atlanıyor): {e}")
def ip_engelle(ip_adresi):
     global engellenen_ipler

     if ip_adresi in engellenen_ipler:
          return
     if sys.platform.startswith("win"):
          kontrol_komutu = f'netsh advfirewall firewall show rule name=\"AI_BLOCK_{ip_adresi}\"'
          sistem_yaniti = os.popen(kontrol_komutu).read()
          if "hiçbir kural eşleşmedi" not in sistem_yaniti.lower() and "no rules match" not in sistem_yaniti.lower():
               print(f"[+] [SİSTEM FARK ETTİ] -> {ip_adresi} zaten Windows Firewall üzerinde engelli, es geçiliyor.")
               engellenen_ipler.add(ip_adresi)
               return
     print(f"[!] [ANOMALİ TESPİT EDİLDİ] -> {ip_adresi} şüpheli hareketler sergiliyor!")
     ip_bilgi_getir(ip_adresi)

     if sys.platform.startswith("linux"):
          komut = f"sudo iptables -A INPUT -s {ip_adresi} -j DROP"
          os.system(komut)
          print(f"[+] {ip_adresi} firewall tarafından ENGELLENDİ (Linux).")
     elif sys.platform.startswith("win"):
          komut_in = f'netsh advfirewall firewall add rule name="AI_BLOCK_{ip_adresi}" dir=in action=block remoteip={ip_adresi}'
          komut_out = f'netsh advfirewall firewall add rule name="AI_BLOCK_OUT_{ip_adresi}" dir=out action=block remoteip={ip_adresi}'
          os.system(komut_in)
          os.system(komut_out)
          print(f"[+] {ip_adresi} Windows Defender Duvarına çift yönlü çakıldı.")
     with open(LOG_DOSYASI, "a", encoding="utf-8") as f:
          f.write(f"{ip_adresi}\n")
     print(f"[+] {ip_adresi} adresi {LOG_DOSYASI} dosyasına kalıcı olarak kaydedildi.")
     engellenen_ipler.add(ip_adresi)
def paket_isleyici(paket):
    
    global AI_MODEL, UYGULAMA_MODELI,ip_sayaclari,engellenen_ipler
    if paket.haslayer(IP):
        kaynak_ip = str(paket[IP].src)
        hedef_ip = str(paket[IP].dst)
        paket_boyutu = len(paket)
        if kaynak_ip in engellenen_ipler:
             
         
             return
        if kaynak_ip.startswith("224.") or kaynak_ip.startswith("239.") or kaynak_ip == "0.0.0.0":
             return
      
        if kaynak_ip.startswith("192.168.") or kaynak_ip.startswith("10.") or kaynak_ip == "127.0.0.1":
            return
        hedef_port = 0
        proto = "Diğer"
        
      

        if paket.haslayer(TCP):
             hedef_port = paket[TCP].dport
             proto = "TCP"
             if paket[TCP].sport == 443 or paket[TCP].dport == 443:
                  return
        elif paket.haslayer(UDP):
             hedef_port = paket[UDP].dport
             proto = "UDP"
        if paket.haslayer(Raw):
             try:
               ham_veri = paket[Raw].load


               if b"Host:" in ham_veri:
                    for guvenli_host in GUVENILIR_HOSTLAR:
                         if guvenli_host.encode() in ham_veri:

                              print(f"[+] BEYAZ LİSTE İZNİ -> {kaynak_ip} adres güvenlir hosta ({guvenli_host.encode()}) gidiyor. Dokunulmadı.")
                              return
               elif proto == "UDP" and (b"\x00" in ham_veri or b"\x01" in ham_veri):
                    return
             except Exception:
                  pass
        if kaynak_ip not in ip_sayaclari:
             ip_sayaclari[kaynak_ip] = 1
        else:
             ip_sayaclari[kaynak_ip] +=1
        
        anlik_istek = ip_sayaclari[kaynak_ip]

        print(f"[{proto}] {kaynak_ip} ===> {hedef_ip}:{hedef_port} | Boyut: {paket_boyutu} | Toplam İstek: {anlik_istek}")
        canli_veri = pandas.DataFrame([[anlik_istek,paket_boyutu]],columns=["istek_sayisi","paket_boyutu"])
        tahmin = AI_MODEL.predict(canli_veri)

        if tahmin[0] == -1:
            canli_veri_uygulama = pandas.DataFrame([[hedef_port, paket_boyutu]], columns=["hedef_port", "paket_boyutu"])
            tahmin_uygulama = UYGULAMA_MODELI.predict(canli_veri_uygulama)
            if tahmin_uygulama[0] == 1 or anlik_istek >= DDOS_PAKET_ESIGI:
                    print("ENGELLEME EKLE BANA ABİİ SIZMASINLAR")
                    ip_engelle(kaynak_ip)
                    if GERI_YANSIT_AKTIFMI:
                         print(f"[OTO EMİR] -> Saldırgana paketler iade ediliyor")
                         paketi_geri_yansit(paket)
                    else:
                         print("[OTO EMİR] Yansıtma kapalı.")
                    del ip_sayaclari[kaynak_ip]
            else:
               
                print("[AI GEÇİŞ İZNİ] -> Yüksek trafik tespit edildi ama yasal uygulama yapısı ile eşleşti.")
        else:
             return
def arka_plan_yaansitici(paket):
     try:
          if paket.haslayer(IP):
               eski_kaynak = paket[IP].src
               eski_hedef = paket[IP].dst

             
               yansiyan_paket = IP(src=eski_hedef, dst=eski_kaynak)

               if paket.haslayer(TCP):
                    yansiyan_paket = yansiyan_paket / TCP(sport=paket[TCP].dport, dport=paket[TCP].sport, flags="R")
               elif paket.haslayer(UDP): 
                    yansiyan_paket = yansiyan_paket / UDP(sport=paket[UDP].dport, dport=paket[UDP].sport)
                    
               if paket.haslayer(Raw):
                    yansiyan_paket = yansiyan_paket / paket[Raw].load
               yansiyan_boyut = len(yansiyan_paket)
               BOMBARDIMAN_ADETI = 1000
               print(f"[SALDIRI BAŞLASINNN] --> Şerefsz {eski_kaynak} adresine kendi silahıyla vuruluyor | Paket boyutu: {yansiyan_boyut} Byte")

               for i in range(BOMBARDIMAN_ADETI):
                    send(yansiyan_paket, verbose=False)
                    print(f"ORAORARORA ATTACKKKK => GEBERRRRRR {eski_kaynak} | FÜZENİN BOYUTU {yansiyan_boyut}")
               print(f"[BOMBARDIMAN TAMAMLANDI] --> {eski_kaynak}")
     except Exception as e:
          print(f"[!] Geri yansıtmada bir hata oluştu: {e}")
def paketi_geri_yansit(paket):
     t = threading.Thread(target=arka_plan_yaansitici,args=(paket,))
     t.daemon = True
     t.start()
if __name__ == "__main__":
        print(banner)
        secim = str(input("[AYAR] Saldırı tespit edildiğinde Yansıtma özelliği çalışsınmı \nE/H : "))
        if secim == "E" or secim == "EVET":
             GERI_YANSIT_AKTIFMI = True
             print("[*] GERI YANSITMA ÖZELLİĞİ AÇIK.")
        else:
             GERI_YANSIT_AKTIFMI = False
             print("[*] GERI YANSITMA ÖZELLİĞİ KAPALI.")
        modeli_hazirla()
        print("\n ETRAFI İZLİYORUM ABİ SEN TAKIL... (durmam için Ctrl + C)")

        try:
             sniff(filter="ip",prn=paket_isleyici,store=False)
        except KeyboardInterrupt:
             print("\n Durdum abi emrinle.")
        