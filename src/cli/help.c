#include "help.h"

#include <string.h>

#include "version.h"

typedef struct
{
    const char *short_opt;
    const char *long_opt;
    const char *arg;
    const char *desc;
    const char *note;
} np_help_option_t;

static void print_banner(FILE *out)
{
    fprintf(out,
"\n"
"    _   __     __  ____            __  \n"
"   / | / /__  / /_/ __ \\___  ___  / /__\n"
"  /  |/ / _ \\/ __/ /_/ / _ \\/ _ \\/ //_/\n"
" / /|  /  __/ /_/ ____/  __/  __/ ,<   \n"
"/_/ |_/\\___/\\__/_/    \\___/\\___/_/|_|  \n"
"\n"
"  v%s | High Performance Network Scanner\n"
"  ─────────────────────────────────────\n\n",
NETPEEK_VERSION_STRING);
}

static void print_title(FILE *out, const char *title)
{
    fprintf(out, "%s:\n", title);
}

static void print_usage(FILE *out, const char *usage)
{
    fprintf(out, "Usage:\n  %s\n\n", usage);
}

static void print_option(const np_help_option_t *opt, FILE *out)
{
    char flag[96];
    char arg[32] = "";

    if (opt->arg && opt->arg[0] != '\0')
        snprintf(arg, sizeof(arg), " %s", opt->arg);

    if (opt->short_opt && opt->long_opt)
        snprintf(flag, sizeof(flag), "-%s, --%s%s", opt->short_opt, opt->long_opt, arg);
    else if (opt->long_opt)
        snprintf(flag, sizeof(flag), "    --%s%s", opt->long_opt, arg);
    else
        snprintf(flag, sizeof(flag), "-%s%s", opt->short_opt, arg);

    fprintf(out, "  %-34s %s", flag, opt->desc);
    if (opt->note && opt->note[0] != '\0')
        fprintf(out, " (%s)", opt->note);
    fputc('\n', out);
}

static void print_group(const char *name,
                        const np_help_option_t *options,
                        size_t count,
                        FILE *out)
{
    print_title(out, name);
    for (size_t i = 0; i < count; i++)
        print_option(&options[i], out);
    fputc('\n', out);
}

static void build_usage(char *buf,
                        size_t bufsz,
                        const char *prog,
                        const char *command,
                        const char *tail)
{
    const char *base = prog ? prog : "netpeek";

    if (command && command[0] != '\0')
    {
        if (tail && tail[0] != '\0')
            snprintf(buf, bufsz, "%s %s %s", base, command, tail);
        else
            snprintf(buf, bufsz, "%s %s", base, command);
        return;
    }

    if (tail && tail[0] != '\0')
        snprintf(buf, bufsz, "%s %s", base, tail);
    else
        snprintf(buf, bufsz, "%s", base);
}

const char *np_help_resolve_command(const char *name)
{
    if (!name || !name[0])
        return NULL;

    if (strcmp(name, "scan") == 0)
        return "scan";
    if (strcmp(name, "npe") == 0)
        return "npe";
    if (strcmp(name, "os-detect") == 0 || strcmp(name, "os") == 0)
        return "os-detect";
    if (strcmp(name, "dns") == 0)
        return "dns";
    if (strcmp(name, "subenum") == 0 || strcmp(name, "subdomain") == 0 || strcmp(name, "sd") == 0)
        return "subenum";
    if (strcmp(name, "diff") == 0)
        return "diff";
    if (strcmp(name, "recon") == 0)
        return "recon";
    if (strcmp(name, "route") == 0)
        return "route";
    if (strcmp(name, "help") == 0)
        return "help";
    if (strcmp(name, "version") == 0)
        return "version";

    return NULL;
}

void np_help_print_overview(const char *prog, FILE *out)
{
    const char *base = prog ? prog : "netpeek";

    print_banner(out);
    print_usage(out, "netpeek <command> [options] <target> [target ...]");

    print_title(out, "Commands");
    fprintf(out, "  scan                              Port scanner\n");
    fprintf(out, "  npe                               NPE scripting engine\n");
    fprintf(out, "  os-detect, os                     OS fingerprint detection\n");
    fprintf(out, "  dns                               DNS enumeration\n");
    fprintf(out, "  subenum, subdomain, sd           Subdomain enumeration\n");
    fprintf(out, "  diff                              Compare two JSON scans\n");
    fprintf(out, "  recon                             Recon framework commands\n");
    fprintf(out, "  route                             Traceroute + hop port scan\n");
    fprintf(out, "  help [command]                    Show top-level or command help\n");
    fprintf(out, "  version                           Show version\n\n");

    print_title(out, "Help Patterns");
    fprintf(out, "  %s --help\n", base);
    fprintf(out, "  %s help scan\n", base);
    fprintf(out, "  %s scan --help\n", base);
    fprintf(out, "  %s scan help\n\n", base);

    print_title(out, "Quick Examples");
    fprintf(out, "  %s scan 192.168.1.1 -p 22,80,443\n", base);
    fprintf(out, "  %s scan 10.0.0.0/24 -sS -p -\n", base);
    fprintf(out, "  %s os-detect -t scanme.nmap.org\n", base);
    fprintf(out, "  %s dns example.com --sub\n", base);
    fprintf(out, "  %s subenum -d example.com --json\n", base);
    fprintf(out, "  %s diff old.json new.json\n", base);
    fprintf(out, "  %s route scanme.nmap.org -p 22,80,443\n", base);
    fprintf(out, "  %s npe --script banner-grab -t scanme.nmap.org -p 22\n\n", base);

    fprintf(out, "Run `%s help <command>` to see all flags for a command.\n", base);
}

void np_help_print_scan_usage(const char *prog, FILE *out)
{
    static const np_help_option_t target_options[] = {
        {"t", "target", "HOST", "Target host/network (repeatable)", "hostname, IP, CIDR"},
        {NULL, "input-list", "FILE", "Read targets from file", "same as -iL"},
        {NULL, "random-targets", "N", "Generate N random IPv4 targets", "same as -iR"},
        {NULL, "exclude", "LIST", "Exclude hosts/networks", "comma separated"},
        {NULL, "excludefile", "FILE", "Exclude hosts/networks from file", NULL},
    };

    static const np_help_option_t scan_type_options[] = {
        {"sS", "syn", NULL, "TCP SYN scan", "requires raw/root"},
        {"sT", "connect", NULL, "TCP connect() scan", NULL},
        {"sA", "ack", NULL, "TCP ACK scan", "requires raw/root"},
        {"sW", "window", NULL, "TCP Window scan", "requires raw/root"},
        {"sM", "maimon", NULL, "TCP Maimon scan", "requires raw/root"},
        {"sU", "udp", NULL, "UDP scan", "requires raw/root for accurate closed detection"},
        {"sN", "null", NULL, "TCP Null scan", "requires raw/root"},
        {"sF", "fin", NULL, "TCP FIN scan", "requires raw/root"},
        {"sX", "xmas", NULL, "TCP Xmas scan", "requires raw/root"},
        {NULL, "scanflags", "FLAGS", "Custom TCP flags", "syn,ack or 0x12"},
        {"sI", "idle", "HOST[:PORT]", "Idle scan via zombie host", "requires raw/root"},
        {"sY", "sctp-init", NULL, "SCTP INIT scan", "requires raw/root"},
        {"sZ", "sctp-cookie", NULL, "SCTP COOKIE-ECHO scan", "requires raw/root"},
        {"sO", "ip-proto", NULL, "IP protocol scan", "requires raw/root"},
    };

    static const np_help_option_t host_discovery_options[] = {
        {"sL", NULL, NULL, "List targets only", NULL},
        {"sn", NULL, NULL, "Ping scan only (disable port scan)", NULL},
        {"Pn", NULL, NULL, "Treat all hosts as online", NULL},
        {"PS", NULL, "[PORTS]", "TCP SYN host discovery", "short-form appended argument"},
        {"PA", NULL, "[PORTS]", "TCP ACK host discovery", "short-form appended argument"},
        {"PU", NULL, "[PORTS]", "UDP host discovery", "short-form appended argument"},
        {"PY", NULL, "[PORTS]", "SCTP host discovery", "short-form appended argument"},
        {"PE", NULL, NULL, "ICMP echo discovery", NULL},
        {"PP", NULL, NULL, "ICMP timestamp discovery", NULL},
        {"PM", NULL, NULL, "ICMP netmask discovery", NULL},
        {"PO", NULL, "[PROTO-LIST]", "IP protocol discovery", "short-form appended argument"},
        {"n", NULL, NULL, "Never resolve DNS", NULL},
        {"R", NULL, NULL, "Always resolve DNS", NULL},
        {NULL, "dns-servers", "LIST", "Custom DNS servers", "comma separated"},
        {NULL, "system-dns", NULL, "Use system DNS resolver", NULL},
        {NULL, "traceroute", NULL, "Trace path to each host", NULL},
        {NULL, "skip-discovery", NULL, "Skip host discovery stage", NULL},
        {NULL, "ping-scan", NULL, "Host discovery only", "same as -sn"},
        {NULL, "list-scan", NULL, "List targets only", "same as -sL"},
    };

    static const np_help_option_t service_options[] = {
        {"sV", NULL, NULL, "Enable service/version detection", NULL},
        {NULL, "version-intensity", "0-9", "Set version probe intensity", NULL},
        {NULL, "version-light", NULL, "Light version probes", "intensity 2"},
        {NULL, "version-all", NULL, "Try all version probes", "intensity 9"},
        {NULL, "version-trace", NULL, "Show version probe trace", NULL},
        {NULL, "tls-info", NULL, "Collect TLS cert/cipher metadata", "post-scan enrichment"},
    };

    static const np_help_option_t perf_options[] = {
        {"p", "ports", "PORTS", "Ports to scan", "80,443 | 1-1000 | -"},
        {"T", "threads", "N", "Probe worker threads", "1..100000"},
        {"W", "workers", "N", "Worker processes", "1..100000"},
        {NULL, "timeout", "MS", "Probe timeout in milliseconds", "1..600000"},
        {NULL, "timing-template", "0-5", "Timing profile preset", NULL},
        {NULL, "fast", NULL, "Nmap-like fast template (-T4)", "drops filtered + threads=NCPU"},
        {NULL, "min-hostgroup", "N", "Minimum concurrent hosts", "1..100000"},
        {NULL, "max-hostgroup", "N", "Maximum concurrent hosts", "1..100000"},
        {NULL, "min-parallelism", "N", "Minimum per-host parallel probes", "1..100000"},
        {NULL, "max-parallelism", "N", "Maximum per-host parallel probes", "1..100000"},
        {NULL, "min-rtt-timeout", "TIME", "Minimum RTT timeout", "ms|s|m|h"},
        {NULL, "max-rtt-timeout", "TIME", "Maximum RTT timeout", "ms|s|m|h"},
        {NULL, "initial-rtt-timeout", "TIME", "Initial RTT timeout", "ms|s|m|h"},
        {NULL, "host-timeout", "TIME", "Maximum time per host", "ms|s|m|h"},
        {NULL, "min-rate", "N", "Minimum send rate (pps)", "1..10000000"},
        {NULL, "max-rate", "N", "Maximum send rate (pps)", "1..10000000"},
        {NULL, "max-retries", "N", "Maximum retransmissions", "0..50"},
        {NULL, "full-mode", NULL, "Enable streaming full-mode engine", "auto-enables -sV and OS detect (SYN/connect supported)"},
        {NULL, "full-rx-threads", "N", "Full-mode receiver threads", "default 2"},
        {NULL, "full-queue-capacity", "N", "Full-mode task queue slots", "default 65536"},
        {NULL, "full-max-inflight", "N", "Full-mode connect inflight cap", "default 4096"},
        {NULL, "udp-fast-path", "MODE", "UDP fast path mode", "auto|on|off"},
        {NULL, "udp-batch-size", "N", "UDP batch syscall size", "1..1024"},
        {NULL, "udp-inflight", "N", "UDP inflight slots per thread", "16..8192"},
        {NULL, "udp-min-probe-interval", "TIME", "UDP probe pacing floor", "ms|s|m|h"},
        {NULL, "udp-linux-advanced", "MODE", "Linux UDP advanced error path", "on|off"},
    };

    static const np_help_option_t output_options[] = {
        {"o", "output", "FILE", "Write output to file", "format can be extension-detected"},
        {"oX", NULL, "FILE", "Write XML output file", "short alias for --xml"},
        {NULL, "json", NULL, "Force JSON output", NULL},
        {NULL, "csv", NULL, "Force CSV output", NULL},
        {NULL, "grep", NULL, "Force greppable output", NULL},
        {NULL, "xml", "FILE", "Write XML output file", NULL},
        {NULL, "html", "FILE", "Write HTML report file", NULL},
        {NULL, "show-closed", NULL, "Include closed ports", "default only shows open"},
        {NULL, "osscan-guess", NULL, "Show low-confidence passive OS hints", NULL},
        {NULL, "osscan-limit", NULL, "Skip OS hint without open+closed evidence", NULL},
        {"v", "verbose", NULL, "Verbose logs/progress", NULL},
    };

    static const np_help_option_t proxy_evasion_options[] = {
        {NULL, "proxy", "URL", "Route probes through proxy", "socks5:// or http://"},
        {NULL, "mtu", "N", "Fragment probes to MTU", "minimum 24"},
        {NULL, "fragment", NULL, "Enable fragmentation (alias)", NULL},
        {NULL, "frag-order", "MODE", "Fragment order", "inorder|random"},
        {"g", "source-port", "PORT", "Fixed source port", "1..65535"},
        {NULL, "decoys", "LIST", "Use decoy source IPs", "IP,IP,ME,... or RND:N"},
        {NULL, "decoy", "LIST", "Decoy alias", NULL},
        {NULL, "spoof-source", "IP", "Spoof source IP", NULL},
        {NULL, "spoof-mac", "MAC", "Spoof source MAC (AF_PACKET)", "mac|vendor|0"},
        {NULL, "data-length", "N", "Random payload padding length", NULL},
        {NULL, "ttl", "N", "Custom TTL", NULL},
        {NULL, "randomize-hosts", NULL, "Shuffle target order", NULL},
        {NULL, "badsum", NULL, "Send invalid checksums", NULL},
        {NULL, "scan-delay", "TIME", "Inter-probe delay", "ms|s|m|h"},
        {NULL, "scan-jitter", "TIME", "Random delay [0,jitter]", "ms|s|m|h"},
        {NULL, "max-scan-delay", "TIME", "Maximum inter-probe delay", "ms|s|m|h"},
        {NULL, "defeat-rst-ratelimit", NULL, "Back off on RST rate limits", NULL},
        {NULL, "randomize-data", NULL, "Randomize payload data", NULL},
    };

    static const np_help_option_t other_options[] = {
        {"h", "help", NULL, "Show this help", NULL},
    };

    char usage[256];
    build_usage(usage, sizeof(usage), prog ? prog : "scan", NULL,
                "[options] <target> [target ...]");

    print_banner(out);
    print_usage(out, usage);

    print_group("Target Input", target_options,
                sizeof(target_options) / sizeof(target_options[0]), out);
    print_group("Scan Type", scan_type_options,
                sizeof(scan_type_options) / sizeof(scan_type_options[0]), out);
    print_group("Host Discovery", host_discovery_options,
                sizeof(host_discovery_options) / sizeof(host_discovery_options[0]), out);
    print_group("Service/Version Detection", service_options,
                sizeof(service_options) / sizeof(service_options[0]), out);
    print_group("Timing/Performance", perf_options,
                sizeof(perf_options) / sizeof(perf_options[0]), out);
    print_group("Output/Display", output_options,
                sizeof(output_options) / sizeof(output_options[0]), out);
    print_group("Proxy/Evasion", proxy_evasion_options,
                sizeof(proxy_evasion_options) / sizeof(proxy_evasion_options[0]), out);
    print_group("Other", other_options,
                sizeof(other_options) / sizeof(other_options[0]), out);

    fprintf(out, "\n  Note: scan modes/probes marked as raw/root require sudo (effective UID 0).\n");

    print_title(out, "Examples");
    fprintf(out, "  %s 192.168.1.1\n", prog ? prog : "scan");
    fprintf(out, "  %s example.com -p 80,443\n", prog ? prog : "scan");
    fprintf(out, "  %s 10.0.0.0/24 -sS -p -\n", prog ? prog : "scan");
    fprintf(out, "  %s -iL targets.txt --exclude 10.0.0.5 --json\n", prog ? prog : "scan");
    fprintf(out, "  %s scanme.nmap.org -sV --version-light\n", prog ? prog : "scan");
}

void np_help_print_npe_usage(const char *prog, FILE *out)
{
    static const np_help_option_t script_options[] = {
        {"s", "script", "EXPR", "Script expression", "required"},
        {"H", "script-help", NULL, "List scripts/help text", "prints metadata table"},
        {"T", "script-threads", "N", "Concurrent script workers", "default: 4"},
        {"t", "target", "HOST", "Target host", "repeatable"},
        {"p", "ports", "PORT", "Single target port", "default: 80"},
        {"j", "json", NULL, "JSON output", NULL},
        {"v", "verbose", NULL, "Verbose logging", NULL},
        {"h", "help", NULL, "Show this help", NULL},
    };

    char usage[256];
    build_usage(usage, sizeof(usage), prog ? prog : "npe", NULL,
                "[options] <target> [target ...]");

    print_banner(out);
    print_usage(out, usage);
    print_group("Options", script_options,
                sizeof(script_options) / sizeof(script_options[0]), out);

    print_title(out, "Examples");
    fprintf(out, "  %s --script banner-grab -t 192.168.1.10 -p 22\n", prog ? prog : "npe");
    fprintf(out, "  %s --script http-robots example.com -p 80\n", prog ? prog : "npe");
    fprintf(out, "  %s --script-help\n", prog ? prog : "npe");
}

void np_help_print_os_detect_usage(const char *prog, FILE *out)
{
    static const np_help_option_t options[] = {
        {"t", "target", "HOST", "Target IPv4 address or hostname", NULL},
        {"p", "port", "PORT", "TCP port to probe", "default: auto-discover"},
        {"s", "sigfile", "PATH", "Signature database file", NULL},
        {"B", "builtin", NULL, "Use compiled-in signatures only", NULL},
        {"o", "output", "FILE", "Write results to file", NULL},
        {NULL, "json", NULL, "JSON output format", NULL},
        {NULL, "csv", NULL, "CSV output format", NULL},
        {NULL, "osscan-guess", NULL, "Show low-confidence passive matches", NULL},
        {NULL, "osscan-limit", NULL, "Skip hosts lacking open+closed evidence", NULL},
        {"v", "verbose", NULL, "Verbose fingerprint detail", NULL},
        {"h", "help", NULL, "Show this help", NULL},
    };

    char usage[256];
    build_usage(usage, sizeof(usage), prog ? prog : "os-detect", NULL,
                "[options] <target>");

    print_banner(out);
    print_usage(out, usage);
    print_group("Options", options, sizeof(options) / sizeof(options[0]), out);
    fprintf(out, "\n  Note: os-detect requires sudo (effective UID 0).\n");

    print_title(out, "Examples");
    fprintf(out, "  %s -t 192.168.1.1 -p 22 -v\n", prog ? prog : "os-detect");
    fprintf(out, "  %s scanme.nmap.org --json\n", prog ? prog : "os-detect");
}

void np_help_print_dns_usage(const char *prog, FILE *out)
{
    print_usage(out, "[options] <domain>");
    static const np_help_option_t options[] = {
        {NULL, "sub", NULL, "Subdomain brute-force", NULL},
        {NULL, "wordlist", "FILE", "Subdomain wordlist", "default data/subdomains-top1k.txt"},
        {NULL, "dns-servers", "LIST", "Custom DNS resolvers", "comma separated"},
        {NULL, "types", "LIST", "Query types", "A,AAAA,CNAME,MX,NS,TXT,SOA,PTR"},
        {NULL, "zone-transfer", NULL, "Attempt AXFR", NULL},
        {NULL, "reverse", "CIDR", "Reverse DNS sweep", NULL},
        {"T", NULL, "N", "Concurrency", "default 50"},
        {NULL, "json", NULL, "JSON output", NULL},
    };
    print_group("Options", options, sizeof(options) / sizeof(options[0]), out);
}

void np_help_print_subenum_usage(const char *prog, FILE *out)
{
    static const np_help_option_t options[] = {
        {"d", "domain", "DOMAIN", "Target domain (repeatable)", "required"},
        {"w", "wordlist", "FILE", "Subdomain wordlist", NULL},
        {NULL, "builtin-wordlist", NULL, "Use built-in default list", NULL},
        {"T", "threads", "N", "Resolver workers", "default 32"},
        {NULL, "timeout", "MS", "DNS timeout in milliseconds", "default 3000"},
        {NULL, "brute", NULL, "Enable brute-force", "default on"},
        {NULL, "axfr", NULL, "Attempt zone transfer", NULL},
        {NULL, "ct", NULL, "Use CT-derived candidate seeds", NULL},
        {NULL, "ct-provider", "NAME", "CT provider", "crtsh|certspotter|all"},
        {NULL, "ct-token", "TOKEN", "Cert Spotter API token", "or NP_CT_CERTSPOTTER_TOKEN"},
        {NULL, "proxy", "URL", "HTTP/SOCKS proxy for CT lookups", NULL},
        {NULL, "reverse", NULL, "Reverse DNS on discovered IPs", NULL},
        {NULL, "permute", NULL, "Generate label mutations", NULL},
        {NULL, "json", NULL, "JSON output", NULL},
        {NULL, "csv", NULL, "CSV output", NULL},
        {NULL, "grep", NULL, "Greppable output", NULL},
        {"o", "output", "FILE", "Write output file", NULL},
        {"v", "verbose", NULL, "Verbose mode", NULL},
    };

    char usage[256];
    build_usage(usage, sizeof(usage), prog ? prog : "subenum", NULL,
                "[options] <domain>");
    print_banner(out);
    print_usage(out, usage);
    print_group("Options", options, sizeof(options) / sizeof(options[0]), out);
}

void np_help_print_diff_usage(const char *prog, FILE *out)
{
    static const np_help_option_t options[] = {
        {"j", "json", NULL, "JSON diff output to stdout", NULL},
        {NULL, "html", "FILE", "Alias for --format html --out FILE", NULL},
        {NULL, "format", "FMT", "Diff output format", "text|json|md|html|xml|sarif|diff"},
        {NULL, "out", "FILE", "Write output to file", NULL},
        {"h", "help", NULL, "Show this help", NULL},
    };

    char usage[256];
    build_usage(usage, sizeof(usage), prog ? prog : "diff", NULL,
                "[options] <scan1.json> <scan2.json>");

    print_banner(out);
    print_usage(out, usage);
    print_group("Options", options, sizeof(options) / sizeof(options[0]), out);

    print_title(out, "Examples");
    fprintf(out, "  %s old.json new.json\n", prog ? prog : "diff");
    fprintf(out, "  %s old.json new.json --json\n", prog ? prog : "diff");
    fprintf(out, "  %s old.json new.json --html diff-report.html\n", prog ? prog : "diff");
    fprintf(out, "  %s old.json new.json --format md --out diff.md\n", prog ? prog : "diff");
}

void np_help_print_recon_usage(const char *prog, FILE *out)
{
    static const np_help_option_t options[] = {
        {NULL, "interval", "TIME", "Watch interval for recon watch", "s|m|h"},
        {NULL, "mode", "MODE", "Authorization mode", "passive|safe|intrusive"},
        {NULL, "style", "PRESET", "Recon output preset", "classic|modern|compact|json|report"},
        {NULL, "format", "FMT", "Recon output format", "text|json|md|html|xml|sarif|diff"},
        {NULL, "output", "FMT", "Alias for --format", "text|json|md|html|xml|sarif|diff"},
        {NULL, "out", "FILE", "Write output to file", NULL},
        {NULL, "pretty", NULL, "Pretty-print output", NULL},
        {NULL, "no-color", NULL, "Disable ANSI colors", NULL},
        {NULL, "compact", NULL, "Compact one-line service view", NULL},
        {NULL, "evidence", NULL, "Include evidence in output", NULL},
        {NULL, "summary-only", NULL, "Show summary footer only", NULL},
        {NULL, "verbose", NULL, "Expand evidence + detail", NULL},
        {NULL, "recon-serial", NULL, "Force serial recon module execution", NULL},
        {NULL, "recon-workers", "N", "Cap recon scheduler workers", "1..100000"},
        {"h", "help", NULL, "Show this help", NULL},
    };

    char usage[256];
    build_usage(usage, sizeof(usage), prog ? prog : "recon", NULL,
                "<run|discover|enum|analyze|diff|report|watch> [options]");

    print_banner(out);
    print_usage(out, usage);
    print_group("Options", options, sizeof(options) / sizeof(options[0]), out);

    print_title(out, "Examples");
    fprintf(out, "  %s run -t scanme.nmap.org -sS -p 22,80,443 --style modern\n", prog ? prog : "recon");
    fprintf(out, "  %s discover -t 10.0.0.0/24 --style compact --summary-only\n", prog ? prog : "recon");
    fprintf(out, "  %s enum -t 10.0.0.0/24 -sS --output json --out enum.json\n", prog ? prog : "recon");
    fprintf(out, "  %s analyze -t scanme.nmap.org -sS --style modern   # includes OS fingerprint\n", prog ? prog : "recon");
    fprintf(out, "  %s watch analyze --interval 24h -t 10.0.0.0/24 -sS --evidence --verbose\n", prog ? prog : "recon");
    fprintf(out, "  %s diff old.json new.json --no-color\n", prog ? prog : "recon");
}

void np_help_print_route_usage(const char *prog, FILE *out)
{
    static const np_help_option_t options[] = {
        {"p", "ports", "SPEC", "Ports to scan on each hop", "e.g. 22,80,443 or 1-1024"},
        {"T", "threads", "N", "Worker threads for hop scan", "default 200"},
        {NULL, "timeout", "MS", "Traceroute + connect timeout", "default 2000"},
        {NULL, "max-hops", "N", "Maximum hops to trace", "1..32"},
        {"o", "output", "FILE", "Write output to file", "stdout suppressed"},
        {NULL, "json", NULL, "Emit JSON output", NULL},
        {"v", "verbose", NULL, "Verbose logging + progress", NULL},
        {"h", "help", NULL, "Show this help", NULL},
    };

    char usage[256];
    build_usage(usage, sizeof(usage), prog ? prog : "route", NULL,
                "[options] <target>");

    print_banner(out);
    print_usage(out, usage);
    print_group("Options", options, sizeof(options) / sizeof(options[0]), out);

    print_title(out, "Examples");
    fprintf(out, "  %s scanme.nmap.org\n", prog ? prog : "route");
    fprintf(out, "  %s scanme.nmap.org -p 22,80,443 -T 300\n", prog ? prog : "route");
    fprintf(out, "  %s scanme.nmap.org --json -o route.json\n", prog ? prog : "route");
    fprintf(out, "  %s scanme.nmap.org -v --timeout 3000\n", prog ? prog : "route");
}

bool np_help_print_command_help(const char *command, const char *prog, FILE *out)
{
    const char *resolved = np_help_resolve_command(command);
    char usage_prog[256];

    if (!resolved)
        return false;

    if (strcmp(resolved, "scan") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "scan", "");
        np_help_print_scan_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "npe") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "npe", "");
        np_help_print_npe_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "os-detect") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "os-detect", "");
        np_help_print_os_detect_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "dns") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "dns", "");
        np_help_print_dns_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "subenum") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "subenum", "");
        np_help_print_subenum_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "diff") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "diff", "");
        np_help_print_diff_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "recon") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "recon", "");
        np_help_print_recon_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "route") == 0)
    {
        build_usage(usage_prog, sizeof(usage_prog), prog, "route", "");
        np_help_print_route_usage(usage_prog, out);
        return true;
    }

    if (strcmp(resolved, "help") == 0)
    {
        np_help_print_overview(prog, out);
        return true;
    }

    if (strcmp(resolved, "version") == 0)
    {
        fprintf(out, "NetPeek %s\n", NETPEEK_VERSION_STRING);
        return true;
    }

    return false;
}
