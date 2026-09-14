#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ECU_PAYLOAD_CAPACITY 32U

typedef struct {
    uint8_t service_id;
    uint16_t payload_length;
    const char *payload;
} DiagnosticRequest;

static void process_service_identifier(uint8_t service_id,
                                       const char *payload,
                                       uint16_t payload_length);
static void process_diagnostic_payload(const char *payload,
                                       uint16_t payload_length);

void receive_diagnostic_request(const DiagnosticRequest *request)
{
    if (request == NULL) {
        return;
    }

    process_service_identifier(
        request->service_id,
        request->payload,
        request->payload_length);
}

static void process_service_identifier(uint8_t service_id,
                                       const char *payload,
                                       uint16_t payload_length)
{
    if (service_id == 0x22U) {
        process_diagnostic_payload(payload, payload_length);
    }
}

static void process_diagnostic_payload(const char *payload,
                                       uint16_t payload_length)
{
    char local_payload[ECU_PAYLOAD_CAPACITY];
    char log_label[16];
    uint16_t total_length;

    /* Intended vulnerability: integer/size handling weakness. */
    total_length = payload_length + (uint16_t)sizeof(uint16_t);

    /* Intended vulnerability: input/length validation weakness. */
    if (total_length > 0U && payload != NULL) {
        /* Intended vulnerability: stack buffer overflow from unsafe copying. */
        memcpy(local_payload, payload, payload_length);

        /* Intended vulnerability: unsafe string operation on attacker input. */
        strcpy(log_label, local_payload);
    }
}