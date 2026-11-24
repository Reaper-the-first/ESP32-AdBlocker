
#include <Arduino.h>
#include "secrets.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <vector>
#include <ctype.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <esp_heap_caps.h>

// ==========================================
// WIFI SETTINGS
// ==========================================

const char* WIFI_SSID = UPSTREAM_WIFI_SSID;
const char* WIFI_PASSWORD = UPSTREAM_WIFI_PASSWORD;

// ==========================================
// ESP32 ACCESS POINT SETTINGS
// ==========================================

const char* AP_SSID = ACCESS_POINT_SSID;
const char* AP_PASSWORD = ACCESS_POINT_PASSWORD;

const IPAddress AP_IP(192, 168, 4, 1);
const IPAddress AP_MASK(255, 255, 255, 0);
const IPAddress AP_LEASE_START(192, 168, 4, 2);

// Wi-Fi event callback: enable NAT when the upstream hotspot gives us an IP.
void onWiFiEvent(arduino_event_id_t event, arduino_event_info_t info) {
    switch (event) {
        case ARDUINO_EVENT_WIFI_STA_START:
            Serial.println("Upstream Wi-Fi station started.");
            break;

        case ARDUINO_EVENT_WIFI_STA_CONNECTED:
            Serial.println("Connected to the upstream Wi-Fi network.");
            break;

        case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            Serial.print("Upstream IP address: ");
            Serial.println(WiFi.localIP());
            if (WiFi.AP.enableNAPT(true)) {
                Serial.println("Internet sharing (NAT) enabled.");
            } else {
                Serial.println("WARNING: Could not enable NAT.");
            }
            break;

        case ARDUINO_EVENT_WIFI_STA_LOST_IP:
        case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
            WiFi.AP.enableNAPT(false);
            Serial.println("Upstream Wi-Fi disconnected; NAT disabled.");
            break;

        default:
            break;
    }
}

// ==========================================
// DNS SETTINGS
// ==========================================

// Use a second public resolver if the primary resolver does not answer.
const IPAddress DNS_UPSTREAM_PRIMARY(1, 1, 1, 1);   // Cloudflare
const IPAddress DNS_UPSTREAM_BACKUP(8, 8, 8, 8);    // Google DNS
const unsigned long DNS_UPSTREAM_TIMEOUT = 2500UL;

const uint16_t DNS_PORT = 53;
const uint16_t UPSTREAM_PORT = 53000;

WiFiUDP dnsServer;
WiFiUDP upstream;
WebServer server(80);

uint8_t dnsBuffer[1232];
uint8_t responseBuffer[1232];

bool blockingEnabled = true;

// ==========================================
// LITTLEFS DOMAIN STORAGE
// ==========================================

std::vector<String> blocklist;
std::vector<String> whitelist;

const char* BLOCKLIST_FILE = "/blocklist.txt";
const char* WHITELIST_FILE = "/whitelist.txt";

// Downloaded blocklist is stored as compact 64-bit hashes in LittleFS.
const char* LARGE_BLOCKLIST_FILE = "/large-blocklist.bin";
const char* LARGE_BLOCKLIST_TEMP = "/large-blocklist.tmp";
const char* LARGE_BLOCKLIST_BACKUP = "/large-blocklist.bak";
const char* LARGE_BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

uint64_t* largeBlockTable = nullptr;
size_t largeBlockTableSize = 0;
size_t largeBlockCount = 0;

// Automatic blocklist updates. The first check happens one minute after startup,
// then repeats every 24 hours while the ESP32 remains powered on.
const unsigned long FIRST_AUTO_UPDATE_DELAY = 60000UL;
const unsigned long BLOCKLIST_UPDATE_INTERVAL = 24UL * 60UL * 60UL * 1000UL;
unsigned long lastBlocklistUpdateAttempt = 0;
bool automaticUpdateHasRun = false;

// ==========================================
// STATISTICS
// ==========================================

unsigned long totalQueries = 0;
unsigned long blockedQueries = 0;
unsigned long allowedQueries = 0;

struct DNSLog {
    char domain[254];
    bool blocked;
};

DNSLog recentLogs[10];

int logPosition = 0;
int logCount = 0;

// ==========================================
// CREATE DOMAIN FILES
// ==========================================

bool createDomainFile(const char* filename) {

    if (LittleFS.exists(filename)) {
        return true;
    }

    File file = LittleFS.open(filename, "w");

    if (!file) {
        Serial.print("Failed to create ");
        Serial.println(filename);
        return false;
    }

    // Add starter domains on first installation.
    if (strcmp(filename, BLOCKLIST_FILE) == 0) {

        file.println("doubleclick.net");
        file.println("googlesyndication.com");
        file.println("googleadservices.com");
        file.println("adservice.google.com");
        file.println("adnxs.com");
        file.println("ads.yahoo.com");
    }

    file.close();

    return true;
}

// ==========================================
// LOAD DOMAIN LIST FROM LITTLEFS
// ==========================================

bool loadDomainList(
    const char* filename,
    std::vector<String>& list
) {

    File file = LittleFS.open(filename, "r");

    if (!file) {
        Serial.print("Could not open ");
        Serial.println(filename);
        return false;
    }

    list.clear();

    while (file.available()) {

        String domain = file.readStringUntil('\n');

        domain.trim();
        domain.toLowerCase();

        // Ignore blank lines and comments.
        if (domain.length() == 0 ||
            domain.startsWith("#")) {
            continue;
        }

        list.push_back(domain);
    }

    file.close();

    Serial.print("Loaded ");
    Serial.print(list.size());
    Serial.print(" domains from ");
    Serial.println(filename);

    return true;
}

// ==========================================
// INITIALIZE LITTLEFS
// ==========================================

bool initializeDomainStorage() {

    Serial.println("Starting LittleFS...");

    // true allows formatting if mounting fails.
    if (!LittleFS.begin(true)) {
        Serial.println("LittleFS initialization failed!");
        return false;
    }

    Serial.println("LittleFS mounted successfully!");

    if (!createDomainFile(BLOCKLIST_FILE)) {
        return false;
    }

    if (!createDomainFile(WHITELIST_FILE)) {
        return false;
    }

    if (!loadDomainList(BLOCKLIST_FILE, blocklist)) {
        return false;
    }

    if (!loadDomainList(WHITELIST_FILE, whitelist)) {
        return false;
    }

    return true;
}

// ==========================================
// CHECK DOMAIN AGAINST A LIST
// ==========================================

bool domainMatches(const char* domain, const String& entry) {

    String checkedDomain = domain;
    checkedDomain.toLowerCase();

    if (checkedDomain == entry) {
        return true;
    }

    if (checkedDomain.length() > entry.length()) {

        int difference =
            checkedDomain.length() - entry.length();

        if (checkedDomain.substring(difference) == entry &&
            checkedDomain.charAt(difference - 1) == '.') {

            return true;
        }
    }

    return false;
}

// ==========================================
// CHECK WHITELIST
// ==========================================

bool isWhitelisted(const char* domain) {

    for (const String& entry : whitelist) {

        if (domainMatches(domain, entry)) {
            return true;
        }
    }

    return false;
}

// ==========================================
// CHECK BLOCKLIST
// ==========================================

bool isBlocked(const char* domain) {

    for (const String& entry : blocklist) {

        if (domainMatches(domain, entry)) {
            return true;
        }
    }

    return false;
}

// ==========================================
// LARGE BLOCKLIST HASH TABLE (PSRAM)
// ==========================================

bool validDomainName(String domain);

uint64_t hashDomainName(const char* domain) {
    // 64-bit FNV-1a hash. Zero is reserved as an empty table slot.
    uint64_t hash = 14695981039346656037ULL;
    while (*domain) {
        hash ^= (uint8_t)tolower((unsigned char)*domain++);
        hash *= 1099511628211ULL;
    }
    return hash == 0 ? 1 : hash;
}

bool insertLargeHash(uint64_t* table, size_t tableSize, uint64_t hash) {
    size_t slot = (size_t)(hash & (tableSize - 1));
    for (size_t probes = 0; probes < tableSize; probes++) {
        if (table[slot] == 0 || table[slot] == hash) {
            table[slot] = hash;
            return true;
        }
        slot = (slot + 1) & (tableSize - 1);
    }
    return false;
}

bool largeHashExists(uint64_t hash) {
    if (!largeBlockTable || largeBlockTableSize == 0) return false;

    size_t slot = (size_t)(hash & (largeBlockTableSize - 1));
    for (size_t probes = 0; probes < largeBlockTableSize; probes++) {
        uint64_t current = largeBlockTable[slot];
        if (current == 0) return false;
        if (current == hash) return true;
        slot = (slot + 1) & (largeBlockTableSize - 1);
    }
    return false;
}

bool isInLargeBlocklist(const char* domain) {
    if (!domain || !largeBlockTable) return false;

    // Check the full hostname and each parent domain.
    char candidate[254];
    strncpy(candidate, domain, sizeof(candidate) - 1);
    candidate[sizeof(candidate) - 1] = '\0';

    char* current = candidate;
    while (*current) {
        if (largeHashExists(hashDomainName(current))) return true;
        char* dot = strchr(current, '.');
        if (!dot) break;
        current = dot + 1;
    }
    return false;
}

bool loadLargeBlocklist() {
    if (!LittleFS.exists(LARGE_BLOCKLIST_FILE)) {
        Serial.println("No downloaded blocklist yet.");
        return false;
    }

    File file = LittleFS.open(LARGE_BLOCKLIST_FILE, "r");
    if (!file) return false;

    size_t bytes = file.size();
    if (bytes < sizeof(uint64_t) || bytes % sizeof(uint64_t) != 0) {
        file.close();
        Serial.println("Downloaded blocklist file is invalid.");
        return false;
    }

    size_t entries = bytes / sizeof(uint64_t);
    size_t needed = 1;
    while (needed < entries * 2) needed <<= 1;

    uint64_t* newTable = (uint64_t*)heap_caps_calloc(
        needed, sizeof(uint64_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
    );

    if (!newTable) {
        file.close();
        Serial.println("Not enough PSRAM for the downloaded blocklist.");
        return false;
    }

    size_t loaded = 0;
    uint64_t hash;
    while (file.available() >= (int)sizeof(uint64_t)) {
        if (file.read((uint8_t*)&hash, sizeof(hash)) != sizeof(hash)) break;
        if (!insertLargeHash(newTable, needed, hash)) break;
        loaded++;
    }
    file.close();

    if (loaded != entries) {
        heap_caps_free(newTable);
        Serial.println("Could not load all downloaded blocklist entries.");
        return false;
    }

    if (largeBlockTable) heap_caps_free(largeBlockTable);
    largeBlockTable = newTable;
    largeBlockTableSize = needed;
    largeBlockCount = loaded;

    Serial.print("Loaded downloaded blocklist entries: ");
    Serial.println(largeBlockCount);
    Serial.print("Hash table memory (bytes): ");
    Serial.println(largeBlockTableSize * sizeof(uint64_t));
    return true;
}

bool parseHostsLine(String line, String& domain) {
    line.trim();
    if (line.length() == 0 || line.startsWith("#")) return false;

    int firstEnd = line.indexOf(' ');
    int tabEnd = line.indexOf('\t');
    if (firstEnd < 0 || (tabEnd >= 0 && tabEnd < firstEnd)) firstEnd = tabEnd;
    if (firstEnd < 0) return false;

    int secondStart = firstEnd;
    while (secondStart < line.length() &&
           (line.charAt(secondStart) == ' ' || line.charAt(secondStart) == '\t')) {
        secondStart++;
    }
    if (secondStart >= line.length()) return false;

    int secondEnd = secondStart;
    while (secondEnd < line.length() &&
           line.charAt(secondEnd) != ' ' && line.charAt(secondEnd) != '\t' &&
           line.charAt(secondEnd) != '#') {
        secondEnd++;
    }

    domain = line.substring(secondStart, secondEnd);
    domain.trim();
    domain.toLowerCase();

    if (!validDomainName(domain)) return false;
    if (domain == "localhost" || domain == "localhost.localdomain" ||
        domain == "broadcasthost" || domain == "ip6-localhost" ||
        domain == "ip6-loopback") return false;
    return true;
}

// Process one complete hosts-file line and save its domain hash.
bool saveDownloadedHostsLine(
    const char* line,
    size_t length,
    File& output,
    size_t& saved
) {
    if (length == 0) return true;

    String textLine;
    textLine.reserve(length);
    for (size_t i = 0; i < length; i++) {
        textLine += line[i];
    }

    String domain;
    if (parseHostsLine(textLine, domain)) {
        uint64_t hash = hashDomainName(domain.c_str());
        if (output.write((const uint8_t*)&hash, sizeof(hash)) != sizeof(hash)) {
            return false;
        }
        saved++;
    }
    return true;
}

bool downloadLargeBlocklist() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Cannot update blocklist: Wi-Fi is disconnected.");
        return false;
    }

    Serial.println("Downloading StevenBlack unified hosts list...");

    WiFiClientSecure secureClient;
    secureClient.setInsecure(); // HTTPS encryption; certificate validation is not enabled.

    HTTPClient http;
    http.setTimeout(30000);
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

    if (!http.begin(secureClient, LARGE_BLOCKLIST_URL)) {
        Serial.println("Could not start HTTPS connection.");
        return false;
    }

    int httpCode = http.GET();
    if (httpCode != HTTP_CODE_OK) {
        Serial.print("Blocklist download failed. HTTP code: ");
        Serial.println(httpCode);
        http.end();
        return false;
    }

    int contentLength = http.getSize();
    Serial.print("HTTP content length: ");
    Serial.println(contentLength);

    LittleFS.remove(LARGE_BLOCKLIST_TEMP);
    File output = LittleFS.open(LARGE_BLOCKLIST_TEMP, "w");
    if (!output) {
        http.end();
        Serial.println("Could not create temporary blocklist file.");
        return false;
    }

    WiFiClient* stream = http.getStreamPtr();

    // Hosts files are line-based. Read raw bytes in small chunks rather than
    // readStringUntil(), which can wait for a newline and stall on network data.
    char lineBuffer[512];
    size_t lineLength = 0;
    bool discardLongLine = false;
    size_t saved = 0;
    size_t received = 0;
    unsigned long lastData = millis();
    unsigned long lastProgress = millis();
    bool writeFailed = false;
    bool timedOut = false;

    while (true) {
        int availableBytes = stream->available();

        if (availableBytes > 0) {
            while (availableBytes-- > 0) {
                int incoming = stream->read();
                if (incoming < 0) break;

                received++;
                lastData = millis();
                char c = (char)incoming;

                if (c == '\n') {
                    if (!discardLongLine) {
                        if (!saveDownloadedHostsLine(
                                lineBuffer, lineLength, output, saved
                            )) {
                            writeFailed = true;
                            break;
                        }
                    }
                    lineLength = 0;
                    discardLongLine = false;
                } else if (!discardLongLine && c != '\r') {
                    if (lineLength < sizeof(lineBuffer) - 1) {
                        lineBuffer[lineLength++] = c;
                    } else {
                        // Ignore an unusually long line safely.
                        discardLongLine = true;
                        lineLength = 0;
                    }
                }

                if (millis() - lastProgress >= 5000) {
                    Serial.print("Downloaded ");
                    Serial.print(received);
                    Serial.print(" bytes; saved ");
                    Serial.print(saved);
                    Serial.println(" domains so far.");
                    lastProgress = millis();
                }

                if (contentLength >= 0 && received >= (size_t)contentLength) {
                    break;
                }
            }

            if (writeFailed ||
                (contentLength >= 0 && received >= (size_t)contentLength)) {
                break;
            }
        } else {
            // A known Content-Length lets us detect completion precisely.
            if (contentLength >= 0 && received >= (size_t)contentLength) {
                break;
            }

            // For chunked/unknown-length responses, the stream closes at EOF.
            if (!http.connected()) {
                break;
            }

            if (millis() - lastData > 60000) {
                timedOut = true;
                break;
            }

            delay(2);
        }
    }

    // Process a final line even if the file does not end with a newline.
    if (!writeFailed && !discardLongLine && lineLength > 0) {
        if (!saveDownloadedHostsLine(lineBuffer, lineLength, output, saved)) {
            writeFailed = true;
        }
    }

    output.close();
    http.end();

    if (writeFailed) {
        Serial.println("LittleFS write failed during download.");
        LittleFS.remove(LARGE_BLOCKLIST_TEMP);
        return false;
    }

    if (timedOut) {
        Serial.println("Blocklist download timed out while waiting for data.");
        LittleFS.remove(LARGE_BLOCKLIST_TEMP);
        return false;
    }

    if (contentLength >= 0 && received < (size_t)contentLength) {
        Serial.println("Download ended before all expected bytes arrived.");
        LittleFS.remove(LARGE_BLOCKLIST_TEMP);
        return false;
    }

    if (saved < 1000) {
        Serial.println("Downloaded list was too small; keeping the previous list.");
        LittleFS.remove(LARGE_BLOCKLIST_TEMP);
        return false;
    }

    Serial.print("Download finished: ");
    Serial.print(received);
    Serial.print(" bytes, ");
    Serial.print(saved);
    Serial.println(" domains parsed.");

    // Keep a backup so a failed replacement does not destroy the old list.
    LittleFS.remove(LARGE_BLOCKLIST_BACKUP);
    bool hadOldFile = LittleFS.exists(LARGE_BLOCKLIST_FILE);

    if (hadOldFile && !LittleFS.rename(LARGE_BLOCKLIST_FILE, LARGE_BLOCKLIST_BACKUP)) {
        LittleFS.remove(LARGE_BLOCKLIST_TEMP);
        Serial.println("Could not back up the previous blocklist.");
        return false;
    }

    if (!LittleFS.rename(LARGE_BLOCKLIST_TEMP, LARGE_BLOCKLIST_FILE)) {
        if (hadOldFile) {
            LittleFS.rename(LARGE_BLOCKLIST_BACKUP, LARGE_BLOCKLIST_FILE);
        }
        Serial.println("Could not install the new blocklist file.");
        return false;
    }

    if (!loadLargeBlocklist()) {
        LittleFS.remove(LARGE_BLOCKLIST_FILE);
        if (hadOldFile) {
            LittleFS.rename(LARGE_BLOCKLIST_BACKUP, LARGE_BLOCKLIST_FILE);
            loadLargeBlocklist();
        }
        return false;
    }

    LittleFS.remove(LARGE_BLOCKLIST_BACKUP);

    Serial.print("Downloaded and loaded domains: ");
    Serial.println(largeBlockCount);
    return true;
}

// ==========================================
// SAVE A DOMAIN LIST TO LITTLEFS
// ==========================================

bool saveDomainList(
    const char* filename,
    const std::vector<String>& list
) {

    String tempFile = String(filename) + ".tmp";

    File file = LittleFS.open(tempFile, "w");

    if (!file) {
        Serial.println("Could not create temporary file!");
        return false;
    }

    for (const String& domain : list) {
        file.println(domain);
    }

    file.close();

    // Replace the old file with the new one.
    LittleFS.remove(filename);

    if (!LittleFS.rename(tempFile, filename)) {
        Serial.println("Could not save domain list!");
        return false;
    }

    Serial.print("Saved ");
    Serial.println(filename);

    return true;
}

// ==========================================
// VALIDATE A DOMAIN NAME
// ==========================================

bool validDomainName(String domain) {

    domain.trim();
    domain.toLowerCase();

    if (domain.length() == 0 || domain.length() > 253) {
        return false;
    }

    if (domain.startsWith(".") || domain.endsWith(".")) {
        return false;
    }

    int labelLength = 0;

    for (int i = 0; i < domain.length(); i++) {

        char c = domain.charAt(i);

        if (c == '.') {

            if (labelLength == 0 || labelLength > 63) {
                return false;
            }

            labelLength = 0;
            continue;
        }

        bool validCharacter =
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-';

        if (!validCharacter) {
            return false;
        }

        if (labelLength == 0 && c == '-') {
            return false;
        }

        labelLength++;

        if (labelLength > 63) {
            return false;
        }
    }

    if (labelLength == 0 || domain.endsWith("-")) {
        return false;
    }

    return true;
}

// ==========================================
// ADD A DOMAIN
// ==========================================

bool addDomain(
    String domain,
    std::vector<String>& list,
    const char* filename
) {

    domain.trim();
    domain.toLowerCase();

    if (!validDomainName(domain)) {
        return false;
    }

    for (const String& existing : list) {

        if (existing == domain) {
            return false;
        }
    }

    list.push_back(domain);

    if (!saveDomainList(filename, list)) {
        list.pop_back();
        return false;
    }

    return true;
}

// ==========================================
// REMOVE A DOMAIN
// ==========================================

bool removeDomain(
    String domain,
    std::vector<String>& list,
    const char* filename
) {

    domain.trim();
    domain.toLowerCase();

    for (size_t i = 0; i < list.size(); i++) {

        if (list[i] == domain) {

            String removedDomain = list[i];

            list.erase(list.begin() + i);

            if (!saveDomainList(filename, list)) {
                list.insert(list.begin() + i, removedDomain);
                return false;
            }

            return true;
        }
    }

    return false;
}

// ==========================================
// EXTRACT DOMAIN FROM DNS PACKET
// ==========================================

bool extractDomain(
    const uint8_t* packet,
    size_t packetLength,
    char* domain,
    size_t domainSize,
    size_t* questionEnd
) {

    if (packetLength < 17 || domainSize < 2) {
        return false;
    }

    // Support one DNS question.
    if (packet[4] != 0 || packet[5] != 1) {
        return false;
    }

    size_t position = 12;
    size_t outputPosition = 0;

    while (position < packetLength) {

        uint8_t labelLength = packet[position++];

        if (labelLength == 0) {
            break;
        }

        // DNS compression is not supported yet.
        if ((labelLength & 0xC0) != 0 ||
            labelLength > 63 ||
            position + labelLength > packetLength) {

            return false;
        }

        if (outputPosition > 0) {

            if (outputPosition + 1 >= domainSize) {
                return false;
            }

            domain[outputPosition++] = '.';
        }

        if (outputPosition + labelLength >= domainSize) {
            return false;
        }

        for (int i = 0; i < labelLength; i++) {

            char c = (char)packet[position++];

            domain[outputPosition++] =
                (char)tolower((unsigned char)c);
        }
    }

    if (position > packetLength ||
        position + 4 > packetLength ||
        outputPosition == 0) {

        return false;
    }

    domain[outputPosition] = '\0';

    *questionEnd = position;

    return true;
}

// Forward declaration: the cache helpers send replies before the full
// sendDNSResponse function appears later in this file.
void sendDNSResponse(const uint8_t* data, size_t length, IPAddress clientIP, uint16_t clientPort);

// ==========================================
// DNS CACHE
// ==========================================

// Keep a small cache in RAM. Entries expire using the DNS answer's TTL.
const size_t DNS_CACHE_CAPACITY = 40;

struct DNSCacheEntry {
    bool valid;
    char domain[254];
    uint16_t queryType;
    uint16_t queryClass;
    uint16_t responseLength;
    unsigned long expiresAt;
    uint8_t response[1232];
};

DNSCacheEntry dnsCache[DNS_CACHE_CAPACITY] = {};
size_t dnsCacheNext = 0;
unsigned long dnsCacheHits = 0;
unsigned long dnsCacheMisses = 0;

// Move past a DNS name, including compressed names in responses.
bool skipDNSName(const uint8_t* packet, size_t length, size_t* position) {
    size_t pos = *position;
    size_t steps = 0;

    while (pos < length && steps++ < 256) {
        uint8_t label = packet[pos];

        if (label == 0) {
            *position = pos + 1;
            return true;
        }

        if ((label & 0xC0) == 0xC0) {
            if (pos + 1 >= length) return false;
            *position = pos + 2;
            return true;
        }

        if ((label & 0xC0) != 0 || label > 63 || pos + 1 + label > length) {
            return false;
        }

        pos += 1 + label;
    }

    return false;
}

// Find the smallest TTL in the answer section. Only cache successful
// responses that contain at least one answer.
uint32_t getDNSResponseTTL(const uint8_t* packet, size_t length) {
    if (length < 12 || (packet[3] & 0x0F) != 0) return 0;

    uint16_t questions = ((uint16_t)packet[4] << 8) | packet[5];
    uint16_t answers = ((uint16_t)packet[6] << 8) | packet[7];
    if (answers == 0 || questions == 0) return 0;

    size_t pos = 12;
    for (uint16_t i = 0; i < questions; i++) {
        if (!skipDNSName(packet, length, &pos) || pos + 4 > length) return 0;
        pos += 4;
    }

    uint32_t smallestTTL = 0xFFFFFFFFUL;
    for (uint16_t i = 0; i < answers; i++) {
        if (!skipDNSName(packet, length, &pos) || pos + 10 > length) return 0;

        uint32_t ttl = ((uint32_t)packet[pos + 4] << 24) |
                       ((uint32_t)packet[pos + 5] << 16) |
                       ((uint32_t)packet[pos + 6] << 8) |
                       packet[pos + 7];
        uint16_t dataLength = ((uint16_t)packet[pos + 8] << 8) | packet[pos + 9];
        pos += 10;
        if (pos + dataLength > length) return 0;
        if (ttl < smallestTTL) smallestTTL = ttl;
        pos += dataLength;
    }

    if (smallestTTL == 0xFFFFFFFFUL) return 0;
    if (smallestTTL > 3600) smallestTTL = 3600;
    return smallestTTL;
}

bool findCachedDNSResponse(
    const char* domain,
    uint16_t queryType,
    uint16_t queryClass,
    const uint8_t* request,
    size_t requestLength,
    IPAddress clientIP,
    uint16_t clientPort
) {
    unsigned long now = millis();

    for (size_t i = 0; i < DNS_CACHE_CAPACITY; i++) {
        DNSCacheEntry& entry = dnsCache[i];
        if (!entry.valid) continue;

        if ((int32_t)(entry.expiresAt - now) <= 0) {
            entry.valid = false;
            continue;
        }

        if (entry.queryType == queryType && entry.queryClass == queryClass &&
            strcmp(entry.domain, domain) == 0) {
            memcpy(responseBuffer, entry.response, entry.responseLength);
            responseBuffer[0] = request[0];
            responseBuffer[1] = request[1];
            sendDNSResponse(responseBuffer, entry.responseLength, clientIP, clientPort);
            dnsCacheHits++;
            Serial.print("[CACHE HIT] ");
            Serial.println(domain);
            return true;
        }
    }

    dnsCacheMisses++;
    return false;
}

void saveDNSCacheEntry(
    const char* domain,
    const uint8_t* request,
    size_t requestLength,
    const uint8_t* response,
    size_t responseLength
) {
    size_t questionEnd = 0;
    char extracted[254];
    if (!extractDomain(request, requestLength, extracted, sizeof(extracted), &questionEnd)) return;
    if (questionEnd + 4 > requestLength || responseLength > sizeof(dnsCache[0].response)) return;

    uint32_t ttl = getDNSResponseTTL(response, responseLength);
    if (ttl == 0) return;

    DNSCacheEntry& entry = dnsCache[dnsCacheNext];
    dnsCacheNext = (dnsCacheNext + 1) % DNS_CACHE_CAPACITY;

    entry.valid = false;
    strncpy(entry.domain, domain, sizeof(entry.domain) - 1);
    entry.domain[sizeof(entry.domain) - 1] = '\0';
    entry.queryType = ((uint16_t)request[questionEnd] << 8) | request[questionEnd + 1];
    entry.queryClass = ((uint16_t)request[questionEnd + 2] << 8) | request[questionEnd + 3];
    entry.responseLength = responseLength;
    memcpy(entry.response, response, responseLength);
    entry.expiresAt = millis() + ttl * 1000UL;
    entry.valid = true;
}

// ==========================================
// SAVE RECENT DNS REQUEST
// ==========================================

void logRequest(const char* domain, bool blocked) {

    strncpy(
        recentLogs[logPosition].domain,
        domain,
        sizeof(recentLogs[logPosition].domain) - 1
    );

    recentLogs[logPosition].domain[
        sizeof(recentLogs[logPosition].domain) - 1
    ] = '\0';

    recentLogs[logPosition].blocked = blocked;

    logPosition = (logPosition + 1) % 10;

    if (logCount < 10) {
        logCount++;
    }
}

// ==========================================
// SEND DNS RESPONSE
// ==========================================

void sendDNSResponse(
    const uint8_t* data,
    size_t length,
    IPAddress clientIP,
    uint16_t clientPort
) {

    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(data, length);
    dnsServer.endPacket();
}

// ==========================================
// SEND BLOCKED RESPONSE (NXDOMAIN)
// ==========================================

void sendBlockedResponse(
    const uint8_t* request,
    size_t requestLength,
    size_t questionEnd,
    IPAddress clientIP,
    uint16_t clientPort
) {

    size_t responseLength = questionEnd + 4;

    if (responseLength > requestLength ||
        responseLength > sizeof(responseBuffer)) {
        return;
    }

    memcpy(responseBuffer, request, responseLength);

    responseBuffer[2] = (request[2] & 0x79) | 0x80;
    responseBuffer[3] = (request[3] & 0x70) | 0x80 | 0x03;

    // No answer or additional records.
    responseBuffer[6] = 0;
    responseBuffer[7] = 0;
    responseBuffer[8] = 0;
    responseBuffer[9] = 0;
    responseBuffer[10] = 0;
    responseBuffer[11] = 0;

    sendDNSResponse(
        responseBuffer,
        responseLength,
        clientIP,
        clientPort
    );
}

// ==========================================
// FORWARD DNS REQUEST TO CLOUDFLARE
// ==========================================

bool forwardDNS(
    const uint8_t* request,
    size_t requestLength,
    IPAddress clientIP,
    uint16_t clientPort,
    const char* domain
) {
    // Try Cloudflare first, then Google DNS if the first server is slow
    // or unreachable. Each attempt uses the same DNS transaction ID.
    const IPAddress resolvers[] = {
        DNS_UPSTREAM_PRIMARY,
        DNS_UPSTREAM_BACKUP
    };

    for (size_t resolverIndex = 0;
         resolverIndex < sizeof(resolvers) / sizeof(resolvers[0]);
         resolverIndex++) {

        const IPAddress& resolver = resolvers[resolverIndex];

        // Discard any delayed response left over from the previous attempt.
        upstream.clear();

        if (!upstream.beginPacket(resolver, DNS_PORT)) {
            Serial.println("Could not start upstream DNS packet.");
            continue;
        }

        size_t bytesSent = upstream.write(request, requestLength);
        bool packetSent = upstream.endPacket();

        if (bytesSent != requestLength || !packetSent) {
            Serial.println("Could not send upstream DNS packet.");
            continue;
        }

        unsigned long startTime = millis();

        while (millis() - startTime < DNS_UPSTREAM_TIMEOUT) {
            // Keep the dashboard responsive while waiting for DNS.
            server.handleClient();

            int packetSize = upstream.parsePacket();

            if (packetSize > 0) {
                IPAddress responseIP = upstream.remoteIP();
                uint16_t responsePort = upstream.remotePort();

                int bytesRead = upstream.read(
                    responseBuffer,
                    sizeof(responseBuffer)
                );

                // Ignore packets that are not from the resolver we queried.
                if (responseIP != resolver || responsePort != DNS_PORT) {
                    continue;
                }

                if (bytesRead < 12) {
                    continue;
                }

                // A DNS response must have the response bit set and match
                // the transaction ID of the original client request.
                if ((responseBuffer[2] & 0x80) == 0 ||
                    responseBuffer[0] != request[0] ||
                    responseBuffer[1] != request[1]) {
                    continue;
                }

                saveDNSCacheEntry(
                    domain, request, requestLength,
                    responseBuffer, bytesRead
                );

                sendDNSResponse(
                    responseBuffer,
                    bytesRead,
                    clientIP,
                    clientPort
                );

                return true;
            }

            delay(1);
        }

        if (resolverIndex + 1 < sizeof(resolvers) / sizeof(resolvers[0])) {
            Serial.println("Primary DNS did not respond; trying backup DNS.");
        }
    }

    return false;
}

// ==========================================
// SEND SERVER FAILURE RESPONSE
// ==========================================

void sendServerFailure(
    const uint8_t* request,
    size_t requestLength,
    IPAddress clientIP,
    uint16_t clientPort
) {

    if (requestLength < 12 ||
        requestLength > sizeof(responseBuffer)) {
        return;
    }

    memcpy(responseBuffer, request, requestLength);

    responseBuffer[2] = (request[2] & 0x79) | 0x80;
    responseBuffer[3] = (request[3] & 0x70) | 0x80 | 0x02;

    responseBuffer[6] = 0;
    responseBuffer[7] = 0;
    responseBuffer[8] = 0;
    responseBuffer[9] = 0;
    responseBuffer[10] = 0;
    responseBuffer[11] = 0;

    sendDNSResponse(
        responseBuffer,
        requestLength,
        clientIP,
        clientPort
    );
}

// ==========================================
// DASHBOARD HTML
// ==========================================

const char DASHBOARD_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ESP32 Pi-hole</title>

<style>
body {
    background: #101827;
    color: white;
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
}

.container {
    max-width: 900px;
    margin: auto;
}

h1 {
    color: #38bdf8;
}

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
}

.card {
    background: #1e293b;
    padding: 20px;
    border-radius: 12px;
}

.number {
    font-size: 30px;
    font-weight: bold;
}

button {
    background: #16a34a;
    color: white;
    border: none;
    padding: 12px 20px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 16px;
    margin: 15px 0;
}

button.off {
    background: #dc2626;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: #1e293b;
    border-radius: 10px;
    overflow: hidden;
}

th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #334155;
    overflow-wrap: anywhere;
}

.blocked {
    color: #f87171;
}

.allowed {
    color: #4ade80;
}

.small {
    color: #94a3b8;
}

input {
    padding: 12px;
    width: 90%;
    max-width: 350px;
    border-radius: 6px;
    border: none;
    margin: 5px 0;
    font-size: 15px;
}

ul {
    padding-left: 20px;
}

li {
    margin: 10px 0;
    overflow-wrap: anywhere;
}

li button {
    padding: 6px 10px;
    margin: 0 0 0 8px;
    font-size: 12px;
}

</style>
</head>

<body>
<div class="container">

<h1>ESP32 Pi-hole</h1>
<p class="small">DNS Ad Blocker Dashboard</p>

<button id="toggle" onclick="toggleBlocking()">
Loading...
</button>

<div class="cards">

<div class="card">
<p>Total Queries</p>
<div class="number" id="total">0</div>
</div>

<div class="card">
<p>Blocked</p>
<div class="number blocked" id="blocked">0</div>
</div>

<div class="card">
<p>Allowed</p>
<div class="number allowed" id="allowed">0</div>
</div>

<div class="card">
<p>DNS Cache Hits</p>
<div class="number" id="cacheHits">0</div>
</div>

<div class="card">
<p>DNS Cache Misses</p>
<div class="number" id="cacheMisses">0</div>
</div>

<div class="card">
<p>Cache Hit Rate</p>
<div class="number" id="cacheRate">0%</div>
<div style="height:10px;background:#334155;border-radius:8px;overflow:hidden;margin-top:10px;">
  <div id="cacheBar" style="height:100%;width:0%;background:#38bdf8;transition:width .3s;"></div>
</div>
</div>

</div>


<h2>Domain Manager</h2>

<div class="card">

<h3>Block a domain</h3>

<form onsubmit="addDomain(event, 'block')">
    <input
        id="blockInput"
        type="text"
        placeholder="example.com"
        required
    >
    <button type="submit">Add to Blocklist</button>
</form>

<h3>Whitelist a domain</h3>

<form onsubmit="addDomain(event, 'allow')">
    <input
        id="allowInput"
        type="text"
        placeholder="example.com"
        required
    >
    <button type="submit">Add to Whitelist</button>
</form>

<p id="domainMessage" class="small"></p>

</div>

<div class="cards">

<div class="card">
    <h3>Blocklist</h3>
    <p id="blockCount">0 domains</p>
    <ul id="blockList"></ul>
</div>

<div class="card">
    <h3>Whitelist</h3>
    <p id="allowCount">0 domains</p>
    <ul id="allowList"></ul>
</div>

</div>

<h2>Large Downloaded Blocklist</h2>

<div class="card">
    <p>Downloaded domains: <strong id="largeBlockCount">0</strong></p>
    <p class="small">Uses PSRAM for fast lookups and LittleFS for permanent storage.</p>
    <button type="button" onclick="updateLargeBlocklist()">Download / Update Blocklist</button>
    <p id="largeBlockMessage" class="small">The first download may take a little while.</p>
</div>

<h2>Recent DNS Activity</h2>


<table>
<thead>
<tr>
<th>Domain</th>
<th>Status</th>
</tr>
</thead>

<tbody id="logs">
<tr><td colspan="2">Waiting for requests...</td></tr>
</tbody>
</table>

<p class="small">Updates automatically every 2 seconds.</p>

</div>

<script>

async function sendDomainRequest(url, domain) {

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            domain: domain
        })
    });

    const message = await response.text();

    document.getElementById('domainMessage').textContent = message;

    if (response.ok) {
        updateDomainLists();
    }
}

async function addDomain(event, type) {

    event.preventDefault();

    const input = document.getElementById(
        type === 'block' ? 'blockInput' : 'allowInput'
    );

    const domain = input.value.trim();

    if (!domain) return;

    const url = type === 'block'
        ? '/api/add-block'
        : '/api/add-whitelist';

    await sendDomainRequest(url, domain);

    input.value = '';
}

async function removeDomain(type, domain) {

    const url = type === 'block'
        ? '/api/remove-block'
        : '/api/remove-whitelist';

    await sendDomainRequest(url, domain);
}

async function updateDomainLists() {

    try {

        const response = await fetch('/api/domains');
        const data = await response.json();

        const blockList = document.getElementById('blockList');
        const allowList = document.getElementById('allowList');

        blockList.innerHTML = '';
        allowList.innerHTML = '';

        document.getElementById('blockCount').textContent =
            data.blocklist.length + ' domains';

        document.getElementById('allowCount').textContent =
            data.whitelist.length + ' domains';

        function displayList(domains, element, type) {

            domains.forEach(domain => {

                const item = document.createElement('li');

                const name = document.createElement('span');
                name.textContent = domain;

                const button = document.createElement('button');
                button.textContent = 'Remove';

                button.onclick = () => removeDomain(type, domain);

                item.appendChild(name);
                item.appendChild(button);

                element.appendChild(item);
            });
        }

        displayList(data.blocklist, blockList, 'block');
        displayList(data.whitelist, allowList, 'allow');

    } catch (error) {

        console.log('Could not load domain lists:', error);
    }
}

async function updateLargeBlocklist() {
    const message = document.getElementById('largeBlockMessage');
    message.textContent = 'Starting download... keep the ESP32 powered on.';
    try {
        const response = await fetch('/api/update-blocklist', { method: 'POST' });
        message.textContent = await response.text();
        setTimeout(refreshLargeBlockCount, 15000);
        setTimeout(refreshLargeBlockCount, 45000);
    } catch (error) {
        message.textContent = 'Could not contact the ESP32.';
    }
}

async function refreshLargeBlockCount() {
    try {
        const response = await fetch('/api/large-blocklist-status');
        const data = await response.json();
        document.getElementById('largeBlockCount').textContent = data.count.toLocaleString();
    } catch (error) {
        console.log('Could not load large blocklist status:', error);
    }
}

async function updateDashboard() {

    try {

        const statusResponse = await fetch('/api/status');
        const status = await statusResponse.json();

        document.getElementById('total').textContent = status.total;
        document.getElementById('blocked').textContent = status.blocked;
        document.getElementById('allowed').textContent = status.allowed;
        document.getElementById('cacheHits').textContent = status.cacheHits;
        document.getElementById('cacheMisses').textContent = status.cacheMisses;
        document.getElementById('cacheRate').textContent = status.cacheRate + '%';
        document.getElementById('cacheBar').style.width = status.cacheRate + '%';

        const button = document.getElementById('toggle');

        button.textContent = status.enabled
            ? 'Blocking Enabled'
            : 'Blocking Disabled';

        button.className = status.enabled ? '' : 'off';

        const logsResponse = await fetch('/api/logs');
        const logs = await logsResponse.json();

        const table = document.getElementById('logs');
        table.innerHTML = '';

        if (logs.length === 0) {
            table.innerHTML =
                '<tr><td colspan="2">No DNS requests yet</td></tr>';
        }

        logs.forEach(log => {

            const row = document.createElement('tr');

            const domainCell = document.createElement('td');
            domainCell.textContent = log.domain;

            const statusCell = document.createElement('td');

            statusCell.textContent = log.blocked
                ? 'BLOCKED'
                : 'ALLOWED';

            statusCell.className = log.blocked
                ? 'blocked'
                : 'allowed';

            row.appendChild(domainCell);
            row.appendChild(statusCell);

            table.appendChild(row);
        });

    } catch (error) {
        console.log('Dashboard update failed:', error);
    }
}

async function toggleBlocking() {

    await fetch('/api/toggle', {
        method: 'POST'
    });

    updateDashboard();
}

updateDashboard();
updateDomainLists();
refreshLargeBlockCount();

setInterval(updateDashboard, 2000);
setInterval(updateDomainLists, 5000);

</script>
</body>
</html>
)rawliteral";

// ==========================================
// UPDATE DOWNLOADED BLOCKLIST
// ==========================================

void handleUpdateLargeBlocklist() {
    server.send(200, "text/plain", "Blocklist update started. Please wait and refresh the dashboard.");
    // The update is performed after the response is sent to the browser.
    delay(100);
    bool success = downloadLargeBlocklist();
    lastBlocklistUpdateAttempt = millis();
    automaticUpdateHasRun = true;
    Serial.println(success ? "Large blocklist update completed." : "Large blocklist update failed.");
}

// ==========================================
// ADD TO BLOCKLIST
// ==========================================

void handleAddBlock() {

    String domain = server.arg("domain");

    if (addDomain(domain, blocklist, BLOCKLIST_FILE)) {
        server.send(200, "text/plain", "Domain added to blocklist!");
    } else {
        server.send(400, "text/plain", "Invalid domain or already exists.");
    }
}

// ==========================================
// REMOVE FROM BLOCKLIST
// ==========================================

void handleRemoveBlock() {

    String domain = server.arg("domain");

    if (removeDomain(domain, blocklist, BLOCKLIST_FILE)) {
        server.send(200, "text/plain", "Domain removed from blocklist!");
    } else {
        server.send(400, "text/plain", "Domain not found or save failed.");
    }
}

// ==========================================
// ADD TO WHITELIST
// ==========================================

void handleAddWhitelist() {

    String domain = server.arg("domain");

    if (addDomain(domain, whitelist, WHITELIST_FILE)) {
        server.send(200, "text/plain", "Domain added to whitelist!");
    } else {
        server.send(400, "text/plain", "Invalid domain or already exists.");
    }
}

// ==========================================
// REMOVE FROM WHITELIST
// ==========================================

void handleRemoveWhitelist() {

    String domain = server.arg("domain");

    if (removeDomain(domain, whitelist, WHITELIST_FILE)) {
        server.send(200, "text/plain", "Domain removed from whitelist!");
    } else {
        server.send(400, "text/plain", "Domain not found or save failed.");
    }
}

// ==========================================
// GET BOTH DOMAIN LISTS
// ==========================================

void handleDomainLists() {

    String json = "{\"blocklist\":[";

    for (size_t i = 0; i < blocklist.size(); i++) {

        if (i > 0) json += ",";

        json += "\"";
        json += blocklist[i];
        json += "\"";
    }

    json += "],\"whitelist\":[";

    for (size_t i = 0; i < whitelist.size(); i++) {

        if (i > 0) json += ",";

        json += "\"";
        json += whitelist[i];
        json += "\"";
    }

    json += "]}";

    server.send(200, "application/json", json);
}

// ==========================================
// LARGE BLOCKLIST STATUS API
// ==========================================

void handleLargeBlocklistStatus() {
    String json = "{\"count\":" + String(largeBlockCount) + "}";
    server.send(200, "application/json", json);
}

// ==========================================
// DASHBOARD PAGE
// ==========================================

void handleDashboard() {
    server.send_P(200, "text/html", DASHBOARD_HTML);
}

// ==========================================
// STATUS API
// ==========================================

void handleStatus() {

    String json = "{";

    json += "\"total\":" + String(totalQueries) + ",";
    json += "\"blocked\":" + String(blockedQueries) + ",";
    json += "\"allowed\":" + String(allowedQueries) + ",";
    json += "\"cacheHits\":" + String(dnsCacheHits) + ",";
    json += "\"cacheMisses\":" + String(dnsCacheMisses) + ",";
    unsigned long cacheLookups = dnsCacheHits + dnsCacheMisses;
    unsigned long cacheRate = cacheLookups > 0
        ? (dnsCacheHits * 100UL) / cacheLookups
        : 0;
    json += "\"cacheRate\":" + String(cacheRate) + ",";
    json += "\"enabled\":";
    json += blockingEnabled ? "true" : "false";

    json += "}";

    server.send(200, "application/json", json);
}

// ==========================================
// RECENT LOGS API
// ==========================================

void handleLogs() {

    String json = "[";

    for (int i = 0; i < logCount; i++) {

        int index = (logPosition - 1 - i + 10) % 10;

        if (i > 0) {
            json += ",";
        }

        json += "{\"domain\":\"";
        json += recentLogs[index].domain;
        json += "\",\"blocked\":";
        json += recentLogs[index].blocked ? "true" : "false";
        json += "}";
    }

    json += "]";

    server.send(200, "application/json", json);
}

// ==========================================
// TOGGLE BLOCKING
// ==========================================

void handleToggle() {

    blockingEnabled = !blockingEnabled;

    Serial.print("Blocking: ");
    Serial.println(blockingEnabled ? "ENABLED" : "DISABLED");

    server.send(200, "text/plain", "OK");
}

// ==========================================
// SETUP
// ==========================================

void setup() {

    Serial.begin(115200);
    delay(1000);

    Serial.println();
    Serial.println("================================");
    Serial.println(" ESP32 DNS AD BLOCKER + WIFI EXTENDER");
    Serial.println("================================");

    // Initialize persistent storage first.
    if (!initializeDomainStorage()) {

        Serial.println("Domain storage failed!");
        return;
    }

    // Load the previously downloaded compact blocklist into PSRAM.
    // If no list exists yet, the normal manual blocklist still works.
    loadLargeBlocklist();

    // Start the ESP32's own Wi-Fi network first.
    // Client devices will use 192.168.4.1 as their DNS server.
    Network.onEvent(onWiFiEvent);

    WiFi.AP.begin();
    WiFi.AP.config(AP_IP, AP_IP, AP_MASK, AP_LEASE_START, AP_IP);
    WiFi.AP.create(AP_SSID, AP_PASSWORD);

    if (!WiFi.AP.waitStatusBits(ESP_NETIF_STARTED_BIT, 10000)) {
        Serial.println("ESP32 access point failed to start!");
        return;
    }

    Serial.println("ESP32 Wi-Fi network started!");
    Serial.print("Network name: ");
    Serial.println(AP_SSID);
    Serial.print("Access point IP / DNS: ");
    Serial.println(AP_IP);

    // Connect to the upstream Wi-Fi network for internet access.
    WiFi.setAutoReconnect(true);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    Serial.print("Connecting to upstream Wi-Fi network");
    unsigned long wifiStart = millis();

    while (WiFi.status() != WL_CONNECTED &&
           millis() - wifiStart < 20000) {
        delay(500);
        Serial.print(".");
    }

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println();
        Serial.println("Could not connect to the upstream Wi-Fi network yet.");
        Serial.println("The ESP32 Wi-Fi network will remain available.");
        Serial.println("Check the hotspot password and restart the ESP32.");
    } else {
        Serial.println();
        Serial.println("Connected to the upstream Wi-Fi network!");
        Serial.print("Upstream IP address: ");
        Serial.println(WiFi.localIP());
        // The STA_GOT_IP event enables NAT.
    }

    // Start DNS server.
    if (!dnsServer.begin(DNS_PORT)) {

        Serial.println("DNS server failed to start!");
        return;
    }

    // Start upstream DNS socket.
    if (!upstream.begin(UPSTREAM_PORT)) {

        Serial.println("Upstream DNS socket failed!");
        return;
    }

    Serial.println("DNS server started on the ESP32 network.");

    // Register dashboard routes.
 
server.on("/", HTTP_GET, handleDashboard);
server.on("/api/status", HTTP_GET, handleStatus);
server.on("/api/logs", HTTP_GET, handleLogs);
server.on("/api/toggle", HTTP_POST, handleToggle);

server.on("/api/domains", HTTP_GET, handleDomainLists);
server.on("/api/large-blocklist-status", HTTP_GET, handleLargeBlocklistStatus);
server.on("/api/update-blocklist", HTTP_POST, handleUpdateLargeBlocklist);

server.on("/api/add-block", HTTP_POST, handleAddBlock);
server.on("/api/remove-block", HTTP_POST, handleRemoveBlock);

server.on("/api/add-whitelist", HTTP_POST, handleAddWhitelist);
server.on("/api/remove-whitelist", HTTP_POST, handleRemoveWhitelist);

    server.begin();

    // Schedule the first automatic update for one minute from now.
    lastBlocklistUpdateAttempt = millis();
    automaticUpdateHasRun = false;

    Serial.println("Web dashboard started!");
    Serial.println("Automatic blocklist updates are enabled.");
    Serial.println("First automatic update will start in about 1 minute.");
    Serial.println("Further updates will run every 24 hours.");
    Serial.println("================================");
}

// ==========================================
// MAIN LOOP
// ==========================================

void loop() {

    server.handleClient();

    // Run the first automatic update one minute after startup, then daily.
    // The current blocklist remains active if the download fails.
    unsigned long updateInterval = automaticUpdateHasRun
        ? BLOCKLIST_UPDATE_INTERVAL
        : FIRST_AUTO_UPDATE_DELAY;

    if (WiFi.status() == WL_CONNECTED &&
        millis() - lastBlocklistUpdateAttempt >= updateInterval) {

        Serial.println();
        Serial.println("Starting scheduled automatic blocklist update...");

        lastBlocklistUpdateAttempt = millis();
        automaticUpdateHasRun = true;

        bool success = downloadLargeBlocklist();
        Serial.println(success
            ? "Scheduled blocklist update completed successfully."
            : "Scheduled blocklist update failed; keeping the previous list.");
    }

    // Keep processing client DNS requests even if the upstream hotspot drops.
    // Blocked domains can still be answered locally; allowed domains will
    // receive SERVFAIL until the internet connection returns.
    int packetSize = dnsServer.parsePacket();

    if (packetSize <= 0) {
        delay(1);
        return;
    }

    if (packetSize > sizeof(dnsBuffer)) {

        Serial.println("DNS packet too large - ignored");
        return;
    }

    IPAddress clientIP = dnsServer.remoteIP();
    uint16_t clientPort = dnsServer.remotePort();

    int bytesRead = dnsServer.read(
        dnsBuffer,
        sizeof(dnsBuffer)
    );

    if (bytesRead < 12) {

        Serial.println("Invalid DNS packet - ignored");
        return;
    }

    char domain[254];
    size_t questionEnd = 0;

    bool validDomain = extractDomain(
        dnsBuffer,
        bytesRead,
        domain,
        sizeof(domain),
        &questionEnd
    );

    // Check whitelist first, then blocklist.
    if (validDomain &&
        blockingEnabled &&
        !isWhitelisted(domain) &&
        (isBlocked(domain) || isInLargeBlocklist(domain))) {

        totalQueries++;
        blockedQueries++;

        logRequest(domain, true);

        Serial.print("[BLOCKED] ");
        Serial.println(domain);

        sendBlockedResponse(
            dnsBuffer,
            bytesRead,
            questionEnd,
            clientIP,
            clientPort
        );

        return;
    }

    // Forward allowed DNS requests.
    totalQueries++;
    allowedQueries++;

    if (validDomain) {

        logRequest(domain, false);

        Serial.print("[ALLOWED] ");
        Serial.println(domain);

    } else {

        logRequest("Unknown DNS query", false);

        Serial.println("[ALLOWED] Unknown DNS query");
    }

    if (validDomain && questionEnd + 4 <= (size_t)bytesRead) {
        uint16_t queryType = ((uint16_t)dnsBuffer[questionEnd] << 8) | dnsBuffer[questionEnd + 1];
        uint16_t queryClass = ((uint16_t)dnsBuffer[questionEnd + 2] << 8) | dnsBuffer[questionEnd + 3];

        if (findCachedDNSResponse(
                domain, queryType, queryClass,
                dnsBuffer, bytesRead, clientIP, clientPort)) {
            return;
        }
    }

    bool forwarded = forwardDNS(
        dnsBuffer,
        bytesRead,
        clientIP,
        clientPort,
        validDomain ? domain : ""
    );

    if (!forwarded) {

        Serial.println("Upstream DNS timeout or error");

        sendServerFailure(
            dnsBuffer,
            bytesRead,
            clientIP,
            clientPort
        );
    }
}
