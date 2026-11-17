# SecReport: User Guide (Roman Urdu)

Yeh guide aap ke liye hai taake aap project chala sakein aur bohot se reports bana kar test kar sakein.

## 1. Chalane se pehle
- Python 3.10 ya naya chahiye (`python --version` se check karein). Koi package install nahi karna.
- PDF banane ke liye Google Chrome, Chromium ya Edge computer par hona chahiye. Na ho to HTML ya Word banayein
  aur browser mein Print > Save as PDF karein.

## 2. Chalana
1. Zip extract karein, terminal us folder mein kholein.
2. Demo data banayein (6 engagements, har report type ka):
   `python3 examples/build_demos.py`  (Windows par `python` ya `py`)
3. Web interface chalayein: `python3 -m secreport serve --workspace demo_workspace`
4. Terminal mein jo **poora link** (`...?token=...`) aaye wo browser mein kholein. Yeh link sirf us run ke liye hai.
   Band karna ho to terminal mein Ctrl+C.
5. Apne asli kaam ke liye `--workspace` ka naam badal dein, jaise `python3 -m secreport serve --workspace mera_kaam`.

## 3. Naya engagement banana (har kaam ki shuruaat)
1. "+ New engagement" dabayein.
2. Report type chunein: OSINT, Red Team, Web Pentest, Bug Bounty ya Executive.
3. **Authorization reference** zaroor likhein (contract, likhit ijazat, ya bug bounty program ki policy ka link).
   Iske baghair scope check kabhi pass nahi hota.
4. In scope mein sirf wohi domain/IP likhein jinki ijazat hai. `*.example.com` aur `10.0.0.0/24` chalta hai.
   Out of scope ko hamesha tarjeeh milti hai.

## 4. Finding banane ke 3 tareeqe
- **Library se:** Findings tab > "Add from library". 41 tayyar templates hain. Yeh draft banti hain aur unmein `TODO:`
  likha hota hai (steps, evidence). Wahan apni asli details likhna zaroori hai, warna approve nahi hoti.
- **Khud likhein:** "+ New finding". CVSS ke dropdown se score khud banta hai.
- **Tool ke results import karein:** Import tab. Nuclei, ZAP, Burp (XML), Nmap (XML). Scope se bahar ki cheezein
  skip hoti hain aur duplicate jur jate hain.

## 5. Review aur approve
- Har finding pehle **Draft** hoti hai. Report mein sirf **Approved** findings aati hain.
- Approve karne wale ka naam likhna zaroori hai. Approve ka matlab: aap ne har baat evidence se check kar li.
- Text badalne par approval khud hat jati hai, taake bina dekhe badlav report mein na jaye.

## 6. Evidence
Evidence tab mein screenshot/log upload karein. Har file ka SHA-256 save hota hai. "Verify all evidence" se pata chalta
hai ke koi file badli to nahi. High/Critical finding ke saath evidence lagana behtar hai (readiness checklist yaad dilata hai).

## 7. Report banana
Report tab:
- **Preview** se dekhein, phir Word / PDF / HTML / Markdown download karein.
- "Include draft" sirf apne andaza ke liye. Client ko hamesha approved wali report dein.
- **Redacted client copy:** IP, e-mail, password/token aur aap ke likhe hue alfaz (client ka naam, hostnames) chhup jate hain.
  Phir bhi bhejne se pehle khud padh lein.

## 8. Retest
Engagement ke upar "Start retest copy" dabayein. Findings draft ban kar copy hoti hain. Status badal kar `verified`
karein, phir home page par "Compare two" se original aur retest ka muqabla dekhein (naya, theek hua, abhi bhi open).

## 9. Free AI ka istemal (optional)
Finding kholein > "Improve the text with a free AI chat". Prompt copy karein, kisi bhi AI chat (Copilot, ChatGPT,
Gemini, Claude) mein paste karein, jawab wapis paste karein. Tool kabhi AI ko khud kuch nahi bhejta. AI jhoot bhi likh sakta
hai (CVE number, link), is liye tool warning deta hai aur approval dobara maangta hai.

## 10. Bohot se reports bana kar test karne ka checklist
Har report type ke liye ek engagement banayein aur yeh cheezein aazmayein:

| Test | Kya hona chahiye |
|---|---|
| Out-of-scope asset ki finding banayein | "not allowed" ka error, finding nahi banti |
| Library finding bina TODO badle approve karein | Refuse hota hai |
| Approved finding ka text badlein | Approval hat jati hai |
| Report mein draft finding | Normal report mein nahi, "Include draft" par DRAFT nishan ke saath |
| Evidence file ke andar ek byte badal dein | "Verify" fail dikhata hai |
| Finding ke text mein `<script>alert(1)</script>` likhein | Report mein sirf text dikhta hai, chalta nahi |
| Redacted copy mein IP `10.1.2.3`, email, `password=abc` | Teeno `[REDACTED]` ho jate hain |
| Wohi Nuclei file do baar import karein | Doosri baar kuch double nahi hota |
| Retest copy + compare | Naya / theek hua / open sahi gine jate hain |
| Report type badal dein (Details tab) | Layout badal jata hai, findings wohi rehti hain |
| Word file Microsoft Word mein kholein | Cover, tables, header/footer theek dikhne chahiye. Koi masla ho to bata dein |

Python tests: `python3 -m unittest discover -s tests`

## 11. Masle aur hal
- **"Open the full link..." likha aata hai:** terminal wala poora link (token samet) kholein.
- **Port busy:** `--port 8800` ke saath chalayein.
- **PDF button band hai:** Chrome/Edge install karein, ya HTML/Word se Print > Save as PDF.
- **Naya terminal, naya link:** har baar server start karne par naya token banta hai.
- **Data kahan hai:** `workspace/<engagement-id>/engagement.json` aur `evidence/` folder. Is folder ko copy kar ke backup lein.
  Client ka data hai, is liye is folder ko apne paas hi rakhein.

## 12. Qanooni baat
Sirf wohi systems test karein jinki aap ke paas **likhit ijazat** ho, ya apni lab (DVWA, Juice Shop, Hack The Box,
TryHackMe). Bina ijazat kisi asli website par testing qanooni jurm ban sakti hai.
