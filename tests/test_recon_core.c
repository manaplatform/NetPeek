#include "test.h"

#include "recon/context.h"
#include "recon/evidence.h"
#include "recon/graph.h"
#include "recon/query.h"

static void test_recon_context_lifecycle(void)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(ctx->run_id != 0);
    ASSERT_EQ_INT(0, (int)np_graph_node_count(ctx));
    ASSERT_EQ_INT(0, (int)np_evidence_count(ctx));

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

static void test_recon_graph_and_evidence(void)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    np_target_t target;
    memset(&target, 0, sizeof(target));
    strncpy(target.ip, "127.0.0.1", sizeof(target.ip) - 1);

    np_port_result_t port;
    memset(&port, 0, sizeof(port));
    port.port = 80;
    strncpy(port.proto, "tcp", sizeof(port.proto) - 1);
    port.state = NP_PORT_OPEN;
    strncpy(port.service, "http", sizeof(port.service) - 1);

    uint64_t host_id = np_graph_add_host(ctx, &target);
    uint64_t svc_id = np_graph_add_service(ctx, &port);
    ASSERT_TRUE(host_id > 0);
    ASSERT_TRUE(svc_id > 0);

    np_graph_link(ctx, host_id, svc_id, "host_has_service");

    np_evidence_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.source_module = "test";
    ev.description = "service banner";
    ev.confidence = 0.90;

    uint64_t ev_id = np_evidence_add(ctx, svc_id, &ev);
    ASSERT_TRUE(ev_id > 0);

    ASSERT_EQ_INT(2, (int)np_graph_node_count(ctx));
    ASSERT_EQ_INT(1, (int)np_graph_edge_count(ctx));
    ASSERT_EQ_INT(1, (int)np_evidence_count(ctx));

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

static void test_recon_graph_service_sync_from_targets(void)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    cfg->target_count = 1;
    cfg->targets = calloc(1, sizeof(np_target_t));
    ASSERT_TRUE(cfg->targets != NULL);

    np_target_t *target = &cfg->targets[0];
    strncpy(target->ip, "127.0.0.1", sizeof(target->ip) - 1);
    strncpy(target->hostname, "localhost", sizeof(target->hostname) - 1);

    target->port_count = 1;
    target->results = calloc(1, sizeof(np_port_result_t));
    ASSERT_TRUE(target->results != NULL);

    target->results[0].port = 443;
    strncpy(target->results[0].proto, "tcp", sizeof(target->results[0].proto) - 1);
    target->results[0].state = NP_PORT_OPEN;
    strncpy(target->results[0].service, "https", sizeof(target->results[0].service) - 1);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    uint64_t host_id = np_graph_add_host(ctx, target);
    uint64_t svc_id = np_graph_add_service(ctx, &target->results[0]);
    ASSERT_TRUE(host_id > 0);
    ASSERT_TRUE(svc_id > 0);
    np_graph_link(ctx, host_id, svc_id, NP_RECON_REL_EXPOSES);

    strncpy(target->results[0].product, "nginx", sizeof(target->results[0].product) - 1);
    strncpy(target->results[0].version, "1.27.4", sizeof(target->results[0].version) - 1);

    ASSERT_EQ_INT(NP_OK, np_graph_sync_services_from_targets(ctx));

    np_service_view_t *services = NULL;
    uint32_t service_count = np_query_services(ctx, host_id, &services);
    ASSERT_EQ_INT(1, (int)service_count);
    ASSERT_TRUE(services != NULL);
    ASSERT_EQ_STR("tcp", services[0].proto);
    ASSERT_EQ_STR("nginx", services[0].product);
    ASSERT_EQ_STR("1.27.4", services[0].version);
    np_query_free(services);

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(test_recon_query_services_uses_per_service_proto)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);
    cfg->scan_type = NP_SCAN_TCP_CONNECT;

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    np_target_t target;
    memset(&target, 0, sizeof(target));
    strncpy(target.ip, "127.0.0.1", sizeof(target.ip) - 1);

    np_port_result_t tcp_svc;
    memset(&tcp_svc, 0, sizeof(tcp_svc));
    tcp_svc.port = 80;
    strncpy(tcp_svc.proto, "tcp", sizeof(tcp_svc.proto) - 1);
    tcp_svc.state = NP_PORT_OPEN;
    strncpy(tcp_svc.service, "http", sizeof(tcp_svc.service) - 1);

    np_port_result_t udp_svc;
    memset(&udp_svc, 0, sizeof(udp_svc));
    udp_svc.port = 53;
    strncpy(udp_svc.proto, "udp", sizeof(udp_svc.proto) - 1);
    udp_svc.state = NP_PORT_OPEN;
    strncpy(udp_svc.service, "domain", sizeof(udp_svc.service) - 1);

    uint64_t host_id = np_graph_add_host(ctx, &target);
    uint64_t tcp_id = np_graph_add_service(ctx, &tcp_svc);
    uint64_t udp_id = np_graph_add_service(ctx, &udp_svc);
    ASSERT_TRUE(host_id > 0);
    ASSERT_TRUE(tcp_id > 0);
    ASSERT_TRUE(udp_id > 0);

    np_graph_link(ctx, host_id, tcp_id, NP_RECON_REL_EXPOSES);
    np_graph_link(ctx, host_id, udp_id, NP_RECON_REL_EXPOSES);

    np_service_view_t *services = NULL;
    uint32_t service_count = np_query_services(ctx, host_id, &services);
    ASSERT_EQ_INT(2, (int)service_count);
    ASSERT_TRUE(services != NULL);

    bool saw_tcp = false;
    bool saw_udp = false;
    for (uint32_t i = 0; i < service_count; i++)
    {
        if (services[i].port == 80)
        {
            ASSERT_EQ_STR("tcp", services[i].proto);
            saw_tcp = true;
        }
        if (services[i].port == 53)
        {
            ASSERT_EQ_STR("udp", services[i].proto);
            saw_udp = true;
        }
    }
    ASSERT_TRUE(saw_tcp);
    ASSERT_TRUE(saw_udp);

    np_query_free(services);
    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

static void test_os_detect_port_discovery_stats_ingest(void)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    cfg->target_count = 1;
    cfg->targets = calloc(1, sizeof(np_target_t));
    ASSERT_TRUE(cfg->targets != NULL);

    np_target_t *tgt = &cfg->targets[0];
    strncpy(tgt->hostname, "manadev.net", sizeof(tgt->hostname) - 1);
    strncpy(tgt->ip, "194.146.123.183", sizeof(tgt->ip) - 1);
    tgt->host_discovered = true;
    tgt->host_up = true;

    /* Simulate port discovery finding 3 open ports */
    uint16_t open_ports[] = {22, 80, 443};
    tgt->port_count = 3;
    tgt->results = calloc(3, sizeof(np_port_result_t));
    ASSERT_TRUE(tgt->results != NULL);
    for (int i = 0; i < 3; i++)
    {
        tgt->results[i].port = open_ports[i];
        tgt->results[i].state = NP_PORT_OPEN;
        strncpy(tgt->results[i].proto, "tcp", sizeof(tgt->results[i].proto) - 1);
    }

    tgt->os_result_valid = true;
    strncpy(tgt->os_result.best_os, "Linux 5.4", sizeof(tgt->os_result.best_os) - 1);
    tgt->os_result.best_confidence = 95.0;

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    /* Graph ingest: host, services, OS */
    uint64_t host_node = np_graph_get_or_add_host(ctx, tgt);
    ASSERT_TRUE(host_node > 0);
    ctx->hosts_seen = 1;

    for (uint32_t i = 0; i < tgt->port_count; i++)
    {
        uint64_t svc_node = np_graph_add_service(ctx, &tgt->results[i]);
        ASSERT_TRUE(svc_node > 0);
        np_graph_link(ctx, host_node, svc_node, NP_RECON_REL_EXPOSES);
        ctx->services_seen++;
    }

    uint64_t os_node = np_graph_add_os(ctx, &tgt->os_result);
    ASSERT_TRUE(os_node > 0);
    np_graph_link(ctx, host_node, os_node, NP_RECON_REL_RUNS);

    /* Verify host view */
    np_host_view_t *hosts = NULL;
    uint32_t host_cnt = np_query_hosts(ctx, &hosts);
    ASSERT_EQ_INT(1, (int)host_cnt);
    ASSERT_TRUE(hosts != NULL);
    ASSERT_EQ_STR("194.146.123.183", hosts[0].ip);

    /* Verify service view */
    np_service_view_t *services = NULL;
    uint32_t svc_cnt = np_query_services(ctx, hosts[0].id, &services);
    ASSERT_EQ_INT(3, (int)svc_cnt);
    ASSERT_TRUE(services != NULL);

    /* Verify OS view */
    np_os_view_t *oses = NULL;
    uint32_t os_cnt = np_query_host_os(ctx, hosts[0].id, &oses);
    ASSERT_EQ_INT(1, (int)os_cnt);
    ASSERT_TRUE(oses != NULL);
    ASSERT_EQ_STR("Linux 5.4", oses[0].name);

    ASSERT_EQ_INT(1, (int)ctx->hosts_seen);
    ASSERT_EQ_INT(3, (int)ctx->services_seen);

    np_query_free(oses);
    np_query_free(services);
    np_query_free(hosts);
    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

void register_recon_core_tests(void)
{
    NP_REGISTER(test_recon_context_lifecycle);
    NP_REGISTER(test_recon_graph_and_evidence);
    NP_REGISTER(test_recon_graph_service_sync_from_targets);
    NP_REGISTER(test_recon_query_services_uses_per_service_proto);
    NP_REGISTER(test_os_detect_port_discovery_stats_ingest);
}
