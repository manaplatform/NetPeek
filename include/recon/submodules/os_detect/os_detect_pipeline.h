#ifndef NP_OS_DETECT_PIPELINE_H
#define NP_OS_DETECT_PIPELINE_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

// Include necessary public types from the rest of the project
#include "recon/submodules/os_detect/os_detect.h"
#include "os_sigload.h"

#ifdef __cplusplus
extern "C" {
#endif



/**
 * @brief Runs the full OS detection pipeline with a pre-loaded signature DB.
 *
 * This is the core pipeline function. It orchestrates all 7 stages of
 * detection, from port discovery to confidence fusion.
 *
 * @param target_ip The IP address of the target host.
 * @param port A target port to start with (can be 0 to rely on discovery).
 * @param sigdb A pointer to a loaded OS signature database. Can be NULL,
 *              in which case fingerprint matching will be skipped.
 * @param result A pointer to an np_os_result_t struct to be filled.
 * @return NP_STATUS_OK on success, or an error code on failure.
 */
np_status_t np_os_detect_pipeline_run(const char *target_ip,
                                      uint16_t port,
                                      const np_os_sigdb_t *sigdb,
                                      np_os_result_t *result);

np_status_t np_os_detect_pipeline_run_ex(const char *target_ip,
                                         uint16_t port,
                                         const uint16_t *open_ports,
                                         uint32_t open_port_count,
                                         uint16_t closed_port,
                                         const np_os_sigdb_t *sigdb,
                                         const void *config,
                                         np_os_result_t *result);

/**
 * @brief Runs the pipeline, automatically finding and loading the signature DB.
 *
 * This convenience wrapper attempts to load the signature database from a
 * specified path or a series of default system paths before running the main
 * pipeline.
 *
 * @param target_ip The IP address of the target host.
 * @param port A target port to start with (can be 0).
 * @param sigdb_path Path to the signature DB. If NULL, default paths are checked.
 * @param result A pointer to an np_os_result_t struct to be filled.
 * @return NP_STATUS_OK on success, or an error code on failure.
 */
np_status_t np_os_detect_pipeline_auto(const char *target_ip,
                                       uint16_t port,
                                       const char *sigdb_path,
                                       np_os_result_t *result);

/**
 * @brief A quick, one-shot detection wrapper for simple use cases.
 *
 * @param target_ip The IP address of the target host.
 * @param port A target port to start with (can be 0).
 * @param os_name_out Buffer to store the resulting OS name.
 * @param os_name_sz Size of the os_name_out buffer.
 * @param confidence_out Pointer to a double to store the confidence score (0-100). Can be NULL.
 * @return NP_STATUS_OK on success, or an error code on failure.
 */
np_status_t np_os_detect_quick(const char *target_ip,
                               uint16_t port,
                               char *os_name_out,
                               size_t os_name_sz,
                               double *confidence_out);

/**
 * @brief Prints a human-readable summary of the detection result to a stream.
 *
 * @param stream The FILE stream to print to (e.g., stdout, stderr).
 * @param result The result structure to print.
 */
void np_os_detect_result_print(FILE *stream,
                               const np_os_result_t *result);

/**
 * @brief Frees any heap-allocated memory within the result struct.
 * @note Currently a no-op, but provided for API completeness and future use.
 *
 * @param result The result structure to free.
 */
void np_os_detect_result_free(np_os_result_t *result);


#ifdef __cplusplus
}
#endif

#endif /* NP_OS_DETECT_PIPELINE_H */
