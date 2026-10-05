#include "api/api_internal.h"

int main(void)
{
    wtq_session_t *session = NULL;
    return wtq_api_session_create_admission(NULL, NULL, &session) == WTQ_ERR_INVALID_ARG
        && session == NULL ? 0 : 1;
}
