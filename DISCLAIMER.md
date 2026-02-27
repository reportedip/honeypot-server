# Haftungsausschluss / Disclaimer

## Deutsch

### 1. Haftungsausschluss für Softwarenutzung
Die Software "ReportedIP Honeypot Server" wird "wie besehen" (AS IS) ohne jegliche ausdrückliche oder stillschweigende Gewährleistung bereitgestellt, einschließlich, aber nicht beschränkt auf die Gewährleistung der Marktgängigkeit, der Eignung für einen bestimmten Zweck und der Nichtverletzung von Rechten Dritter.

In keinem Fall sind die Autoren oder Urheberrechtsinhaber (Patrick Schlesinger, reportedip.de) haftbar für Ansprüche, Schäden oder andere Verpflichtungen, ob in einer Vertragsklage, unerlaubten Handlung oder anderweitig, die sich aus, aus oder in Verbindung mit der Software oder der Nutzung oder anderen Geschäften mit der Software ergeben.

### 2. Rechtliche Zulässigkeit
Der Betrieb eines Honeypots kann in bestimmten Jurisdiktionen rechtlichen Einschränkungen unterliegen (z.B. "Hackerparagrafen", Telekommunikationsgesetze, Datenschutz). **Der Betreiber dieser Software ist allein verantwortlich für die Einhaltung aller anwendbaren lokalen, nationalen und internationalen Gesetze.**

Die Autoren übernehmen keine Haftung für rechtliche Konsequenzen, die aus dem Betrieb, der Datenerfassung oder der Weiterleitung von Daten an Dritte (z.B. reportedip.de API) entstehen.

### 3. Datenschutz (DSGVO/GDPR)
Diese Software erfasst, speichert und überträgt IP-Adressen und andere technische Daten von Besuchern, die als potenziell bösartig eingestuft werden. IP-Adressen können als personenbezogene Daten gelten.
- Der Betreiber ist als "Verantwortlicher" im Sinne der DSGVO für die rechtmäßige Verarbeitung dieser Daten zuständig.
- Die Nutzung der reportedip.de API zur Meldung von Angriffen erfolgt auf eigene Verantwortung des Betreibers.
- Es wird empfohlen, eine entsprechende Datenschutzerklärung auf dem Honeypot-System bereitzustellen.

### 4. Sicherheitsrisiken
Diese Software ist dazu konzipiert, Angriffe anzuziehen und zu protokollieren. Obwohl Sicherheitsmaßnahmen implementiert wurden:
- Es besteht immer ein Restrisiko, dass ein Honeypot selbst kompromittiert wird.
- Die Autoren haften nicht für Schäden am Host-System, Netzwerk, oder Datenverlust durch erfolgreiche Angriffe auf den Honeypot.
- Der Betrieb sollte immer in einer isolierten Umgebung (z.B. DMZ, separate VM/VLAN) erfolgen.

### 5. Fehlalarme (False Positives)
Die Erkennungslogik (Analyzers) arbeitet heuristisch. Es kann nicht ausgeschlossen werden, dass legitime Zugriffe fälschlicherweise als Angriff klassifiziert und gemeldet werden. Die Autoren haften nicht für Schäden, die durch solche Fehlklassifizierungen entstehen (z.B. IP-Blockaden durch Dritte).

---

## English

### 1. Disclaimer of Warranty
The software "ReportedIP Honeypot Server" is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement.

In no event shall the authors or copyright holders (Patrick Schlesinger, reportedip.de) be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

### 2. Legal Compliance
Running a honeypot may be subject to legal restrictions in certain jurisdictions (e.g., anti-hacking laws, telecommunications laws, privacy regulations). **The operator of this software is solely responsible for compliance with all applicable local, national, and international laws.**

The authors assume no liability for legal consequences arising from the operation, data collection, or forwarding of data to third parties (e.g., reportedip.de API).

### 3. Data Privacy (GDPR)
This software collects, stores, and transmits IP addresses and other technical data of visitors classified as potentially malicious. IP addresses may be considered personal data.
- The operator is the "Controller" under GDPR responsible for the lawful processing of this data.
- Using the reportedip.de API to report attacks is done at the operator's own risk and responsibility.
- It is recommended to provide an appropriate privacy policy on the honeypot system.

### 4. Security Risks
This software is designed to attract and log attacks. Although security measures have been implemented:
- There is always a residual risk that a honeypot itself may be compromised.
- The authors are not liable for damage to the host system, network, or data loss resulting from successful attacks on the honeypot.
- Operation should always take place in an isolated environment (e.g., DMZ, separate VM/VLAN).

### 5. False Positives
The detection logic (Analyzers) works heuristically. It cannot be ruled out that legitimate access is incorrectly classified and reported as an attack. The authors are not liable for damages resulting from such misclassifications (e.g., IP blocks by third parties).
